//! Asynchronous network node for the `freesignal` relay infrastructure.
//!
//! This module exposes an Axum-based HTTP server that plays two roles at once:
//!
//!  - **Client ingress/egress**: authenticated clients deposit and retrieve
//!    end-to-end encrypted envelopes under `/api/client/*`.
//!  - **Node relay**: peer nodes forward envelopes addressed to clients that
//!    are homed on this node under `/api/node/*`.
//!
//! The transport layer has *no* opinion on how messages are persisted or how
//! clients/nodes are authenticated — that is fully decoupled behind the
//! [`MessageStore`], [`ClientAuthenticator`], [`NodeAuthenticator`] and
//! [`NodeDirectory`] traits, mirroring the way [`crate::SessionKeyStore`] and
//! [`crate::KeyExchangeStore`] decouple persistence in the rest of this crate.
//!
//! ## Cargo.toml additions
//!
//! ```toml
//! axum = "0.7"
//! tokio = { version = "1", features = ["rt-multi-thread", "net", "macros"] }
//! serde = { version = "1", features = ["derive"] }
//! serde_json = "1"
//! async-trait = "0.1"
//! reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls"] }
//! base64 = "0.22"
//! rand_core = { version = "0.6", features = ["std"] } # already a dependency of x3dh.rs
//! subtle = "2"                                        # already a dependency of double_ratchet.rs
//! ```
//!
//! And add `pub mod node;` alongside the existing `mod double_ratchet;` /
//! `mod x3dh;` declarations in `lib.rs`.

use async_trait::async_trait;
use axum::{
    Json, Router,
    extract::{FromRef, FromRequestParts, Path, State},
    http::{StatusCode, header::AUTHORIZATION, request::Parts},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Domain-level errors produced anywhere in the node. Every variant maps to
/// a concrete HTTP status via [`IntoResponse`] so handlers can simply use
/// `?` and let the framework do the translation.
#[derive(Debug, Clone)]
pub enum NodeError {
    /// Missing, malformed, or invalid credential.
    Unauthorized,
    /// Credential valid, but does not grant access to the requested resource.
    Forbidden,
    /// The requested resource (e.g. an unknown recipient) does not exist.
    NotFound,
    /// The recipient is not known to this node or its directory.
    UnknownRecipient,
    /// The request body failed validation.
    InvalidRequest(String),
    /// The persistence layer failed.
    Storage(String),
    /// Relaying to a peer node failed (unreachable, rejected, timed out).
    Relay(String),
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthorized => write!(f, "missing or invalid credentials"),
            Self::Forbidden => write!(f, "not permitted to access this resource"),
            Self::NotFound => write!(f, "resource not found"),
            Self::UnknownRecipient => write!(f, "recipient is not known to this network"),
            Self::InvalidRequest(msg) => write!(f, "invalid request: {msg}"),
            Self::Storage(msg) => write!(f, "storage error: {msg}"),
            Self::Relay(msg) => write!(f, "relay error: {msg}"),
        }
    }
}

impl std::error::Error for NodeError {}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

impl IntoResponse for NodeError {
    fn into_response(self) -> Response {
        let status = match &self {
            NodeError::Unauthorized => StatusCode::UNAUTHORIZED,
            NodeError::Forbidden => StatusCode::FORBIDDEN,
            NodeError::NotFound | NodeError::UnknownRecipient => StatusCode::NOT_FOUND,
            NodeError::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            NodeError::Storage(_) => StatusCode::INTERNAL_SERVER_ERROR,
            NodeError::Relay(_) => StatusCode::BAD_GATEWAY,
        };
        let body = ErrorBody {
            error: self.to_string(),
        };
        (status, Json(body)).into_response()
    }
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// An opaque, already-encrypted envelope. The node never inspects
/// `header`/`ciphertext` — they are produced by [`crate::HeaderKey`] /
/// [`crate::MessageKey`] on the client and are relayed as-is. Binary fields
/// are base64-encoded for JSON transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    pub message_id: String,
    pub sender_id: String,
    pub recipient_id: String,
    /// Base64-encoded output of `HeaderKey::encrypt_header`.
    pub header: String,
    /// Base64-encoded output of `MessageKey::encrypt_padded_payload`.
    pub ciphertext: String,
    pub timestamp: u64,
}

#[derive(Debug, Deserialize)]
pub struct DepositMessageRequest {
    pub recipient_id: String,
    pub header: String,
    pub ciphertext: String,
}

#[derive(Debug, Serialize)]
pub struct DepositMessageResponse {
    pub message_id: String,
    /// True if the message had to be forwarded to a peer node rather than
    /// being stored locally.
    pub relayed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FetchMessagesResponse {
    pub messages: Vec<EncryptedEnvelope>,
}

#[derive(Debug, Deserialize)]
pub struct AckMessagesRequest {
    pub message_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RelayMessageRequest {
    pub envelope: EncryptedEnvelope,
    pub origin_node_id: String,
}

// ---------------------------------------------------------------------------
// Persistence trait
// ---------------------------------------------------------------------------

/// Storage abstraction for pending envelopes. Implementations are expected
/// to be cheap to clone (typically an `Arc`-wrapped handle to a DB pool) and
/// safe to share across tasks.
#[async_trait]
pub trait MessageStore: Send + Sync {
    async fn save_message(&self, envelope: EncryptedEnvelope) -> Result<(), NodeError>;
    async fn fetch_messages(&self, recipient_id: &str) -> Result<Vec<EncryptedEnvelope>, NodeError>;
    async fn ack_messages(&self, recipient_id: &str, message_ids: &[String]) -> Result<(), NodeError>;
}

// ---------------------------------------------------------------------------
// Authentication traits
// ---------------------------------------------------------------------------

/// Verifies a client-presented credential (bearer token / API key) and
/// resolves it to the `client_id` it is authorized to act as. Kept
/// independent of [`MessageStore`] so auth can be backed by a completely
/// different system (OAuth introspection, a signed JWT, a database, ...).
#[async_trait]
pub trait ClientAuthenticator: Send + Sync {
    async fn authenticate(&self, credential: &str) -> Result<String, NodeError>;
}

/// Verifies that an inbound relay request genuinely originates from the
/// peer node it claims to be. A minimal constant-time shared-secret
/// implementation is provided in [`mock::StaticNodeAuthenticator`]; production
/// deployments should prefer per-node asymmetric signatures (e.g. sign the
/// request body with the sending node's `ed25519_dalek::SigningKey` and
/// verify with its known `VerifyingKey`).
#[async_trait]
pub trait NodeAuthenticator: Send + Sync {
    async fn verify(&self, node_id: &str, token: &str) -> Result<(), NodeError>;
}

/// Resolves which node currently owns a given client, so a deposit can
/// either be stored locally or forwarded to the right peer.
#[async_trait]
pub trait NodeDirectory: Send + Sync {
    async fn locate(&self, client_id: &str) -> Result<NodeLocation, NodeError>;
}

#[derive(Debug, Clone)]
pub enum NodeLocation {
    /// The client is homed on this node; store locally.
    Local,
    /// The client is homed on a peer node; forward via its relay endpoint.
    Remote { node_id: String, relay_url: String },
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// Static configuration for this node instance.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// This node's own identifier, sent as `X-Node-Id` on outbound relays.
    pub node_id: String,
    /// Token this node presents to peers when relaying (must be accepted by
    /// the peer's [`NodeAuthenticator`]).
    pub outbound_node_token: String,
}

/// Application state shared across all handlers. Every field is behind an
/// `Arc`, so `AppState` itself is cheap to `Clone` (required by Axum's
/// `State` extractor).
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn MessageStore>,
    pub client_auth: Arc<dyn ClientAuthenticator>,
    pub node_auth: Arc<dyn NodeAuthenticator>,
    pub directory: Arc<dyn NodeDirectory>,
    pub http_client: reqwest::Client,
    pub config: Arc<NodeConfig>,
}

// ---------------------------------------------------------------------------
// Extractors (middleware equivalents)
// ---------------------------------------------------------------------------

/// Extractor that authenticates a client via `Authorization: Bearer <token>`
/// and yields the resolved `client_id`. Any handler that takes this as an
/// argument automatically rejects unauthenticated calls with `401` before
/// the handler body ever runs.
pub struct AuthenticatedClient(pub String);

#[axum::async_trait]
impl<S> FromRequestParts<S> for AuthenticatedClient
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = NodeError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        let header_value = parts
            .headers
            .get(AUTHORIZATION)
            .ok_or(NodeError::Unauthorized)?;
        let header_str = header_value.to_str().map_err(|_| NodeError::Unauthorized)?;
        let token = header_str
            .strip_prefix("Bearer ")
            .ok_or(NodeError::Unauthorized)?;

        let client_id = app_state.client_auth.authenticate(token).await?;
        Ok(AuthenticatedClient(client_id))
    }
}

/// Extractor that authenticates an inbound node-to-node relay call via the
/// `X-Node-Id` / `X-Node-Token` headers. Client credentials are never
/// checked here — this is a separate trust boundary for server-to-server
/// traffic, per spec.
pub struct AuthenticatedNode(pub String);

#[axum::async_trait]
impl<S> FromRequestParts<S> for AuthenticatedNode
where
    AppState: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = NodeError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app_state = AppState::from_ref(state);

        let node_id = parts
            .headers
            .get("x-node-id")
            .and_then(|v| v.to_str().ok())
            .ok_or(NodeError::Unauthorized)?
            .to_string();
        let token = parts
            .headers
            .get("x-node-token")
            .and_then(|v| v.to_str().ok())
            .ok_or(NodeError::Unauthorized)?;

        app_state.node_auth.verify(&node_id, token).await?;
        Ok(AuthenticatedNode(node_id))
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /api/client/messages` — deposit a message for another client.
///
/// If the recipient is homed on this node, the envelope is stored directly.
/// Otherwise it is forwarded over HTTP to the owning peer's relay endpoint.
pub async fn deposit_message(
    State(state): State<AppState>,
    AuthenticatedClient(sender_id): AuthenticatedClient,
    Json(req): Json<DepositMessageRequest>,
) -> Result<Json<DepositMessageResponse>, NodeError> {
    if req.recipient_id.trim().is_empty() {
        return Err(NodeError::InvalidRequest("recipient_id is required".into()));
    }
    BASE64
        .decode(&req.header)
        .map_err(|_| NodeError::InvalidRequest("header must be valid base64".into()))?;
    BASE64
        .decode(&req.ciphertext)
        .map_err(|_| NodeError::InvalidRequest("ciphertext must be valid base64".into()))?;

    let envelope = EncryptedEnvelope {
        message_id: generate_message_id(),
        sender_id,
        recipient_id: req.recipient_id.clone(),
        header: req.header,
        ciphertext: req.ciphertext,
        timestamp: unix_timestamp(),
    };

    match state.directory.locate(&req.recipient_id).await? {
        NodeLocation::Local => {
            state.store.save_message(envelope.clone()).await?;
            Ok(Json(DepositMessageResponse {
                message_id: envelope.message_id,
                relayed: false,
            }))
        }
        NodeLocation::Remote { relay_url, .. } => {
            relay_to_peer(&state, &relay_url, envelope.clone()).await?;
            Ok(Json(DepositMessageResponse {
                message_id: envelope.message_id,
                relayed: true,
            }))
        }
    }
}

/// `GET /api/client/messages/:client_id` — fetch pending messages.
///
/// The authenticated caller must match the `client_id` path segment; a
/// mismatch is a `403`, not a `404`, so callers can't distinguish "wrong
/// owner" from "unknown client" by status code alone... actually it is
/// intentionally explicit here since leaking existence of a client_id is not
/// a meaningful confidentiality boundary in this protocol.
pub async fn fetch_messages(
    State(state): State<AppState>,
    AuthenticatedClient(auth_client_id): AuthenticatedClient,
    Path(client_id): Path<String>,
) -> Result<Json<FetchMessagesResponse>, NodeError> {
    if !bool::from(auth_client_id.as_bytes().ct_eq(client_id.as_bytes())) {
        return Err(NodeError::Forbidden);
    }

    let messages = state.store.fetch_messages(&client_id).await?;
    Ok(Json(FetchMessagesResponse { messages }))
}

/// `DELETE /api/client/messages/:client_id` (acknowledge / clear fetched
/// messages) — optional but included since a store without a way to drain
/// it grows unbounded.
pub async fn ack_messages(
    State(state): State<AppState>,
    AuthenticatedClient(auth_client_id): AuthenticatedClient,
    Path(client_id): Path<String>,
    Json(req): Json<AckMessagesRequest>,
) -> Result<StatusCode, NodeError> {
    if !bool::from(auth_client_id.as_bytes().ct_eq(client_id.as_bytes())) {
        return Err(NodeError::Forbidden);
    }
    state.store.ack_messages(&client_id, &req.message_ids).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/node/relay` — accept a message forwarded by a peer node.
///
/// Client authentication is intentionally bypassed here (the caller is a
/// node, not a client) but the relay itself must pass [`NodeAuthenticator`].
pub async fn relay_message(
    State(state): State<AppState>,
    AuthenticatedNode(_origin_node_id): AuthenticatedNode,
    Json(req): Json<RelayMessageRequest>,
) -> Result<StatusCode, NodeError> {
    match state.directory.locate(&req.envelope.recipient_id).await? {
        NodeLocation::Local => {
            state.store.save_message(req.envelope).await?;
            Ok(StatusCode::ACCEPTED)
        }
        // A well-behaved peer should never send us a message for a client we
        // don't own; treat that as a routing/config error upstream rather
        // than silently re-forwarding (which risks relay loops).
        NodeLocation::Remote { .. } => {
            Err(NodeError::Relay("recipient is not homed on this node".into()))
        }
    }
}

async fn relay_to_peer(
    state: &AppState,
    relay_url: &str,
    envelope: EncryptedEnvelope,
) -> Result<(), NodeError> {
    let body = RelayMessageRequest {
        envelope,
        origin_node_id: state.config.node_id.clone(),
    };

    let response = state
        .http_client
        .post(relay_url)
        .header("x-node-id", &state.config.node_id)
        .header("x-node-token", &state.config.outbound_node_token)
        .json(&body)
        .send()
        .await
        .map_err(|e| NodeError::Relay(format!("peer node unreachable: {e}")))?;

    if !response.status().is_success() {
        return Err(NodeError::Relay(format!(
            "peer node rejected relay with status {}",
            response.status()
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Router / server bootstrap
// ---------------------------------------------------------------------------

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/api/client/messages", post(deposit_message))
        .route(
            "/api/client/messages/:client_id",
            get(fetch_messages).delete(ack_messages),
        )
        .route("/api/node/relay", post(relay_message))
        .with_state(state)
}

/// Binds and serves the node until the process is terminated.
pub async fn run_node(state: AppState, addr: SocketAddr) -> std::io::Result<()> {
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn generate_message_id() -> String {
    let mut bytes = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the epoch")
        .as_secs()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// ---------------------------------------------------------------------------
// In-memory mocks (example usage / integration tests)
// ---------------------------------------------------------------------------

/// Minimal in-memory implementations of every trait in this module, useful
/// for local development, integration tests, and as a template for real
/// (database-backed, config-backed) implementations.
pub mod mock {
    use super::*;
    use std::collections::HashSet;
    use tokio::sync::RwLock;

    #[derive(Default)]
    pub struct InMemoryMessageStore {
        inbox: RwLock<HashMap<String, Vec<EncryptedEnvelope>>>,
    }

    #[async_trait]
    impl MessageStore for InMemoryMessageStore {
        async fn save_message(&self, envelope: EncryptedEnvelope) -> Result<(), NodeError> {
            self.inbox
                .write()
                .await
                .entry(envelope.recipient_id.clone())
                .or_default()
                .push(envelope);
            Ok(())
        }

        async fn fetch_messages(&self, recipient_id: &str) -> Result<Vec<EncryptedEnvelope>, NodeError> {
            Ok(self
                .inbox
                .read()
                .await
                .get(recipient_id)
                .cloned()
                .unwrap_or_default())
        }

        async fn ack_messages(&self, recipient_id: &str, message_ids: &[String]) -> Result<(), NodeError> {
            if let Some(list) = self.inbox.write().await.get_mut(recipient_id) {
                list.retain(|m| !message_ids.contains(&m.message_id));
            }
            Ok(())
        }
    }

    /// Static bearer-token → client_id map. Real deployments would replace
    /// this with a JWT/OAuth check or a database lookup.
    #[derive(Default)]
    pub struct StaticTokenAuthenticator {
        pub tokens: HashMap<String, String>,
    }

    #[async_trait]
    impl ClientAuthenticator for StaticTokenAuthenticator {
        async fn authenticate(&self, credential: &str) -> Result<String, NodeError> {
            self.tokens
                .get(credential)
                .cloned()
                .ok_or(NodeError::Unauthorized)
        }
    }

    /// Constant-time, pre-shared-secret node authenticator. Swap for
    /// signature verification (e.g. `ed25519_dalek::VerifyingKey::verify_strict`
    /// over the request body) in production.
    #[derive(Default)]
    pub struct StaticNodeAuthenticator {
        pub secrets: HashMap<String, String>,
    }

    #[async_trait]
    impl NodeAuthenticator for StaticNodeAuthenticator {
        async fn verify(&self, node_id: &str, token: &str) -> Result<(), NodeError> {
            let expected = self.secrets.get(node_id).ok_or(NodeError::Unauthorized)?;
            if bool::from(expected.as_bytes().ct_eq(token.as_bytes())) {
                Ok(())
            } else {
                Err(NodeError::Unauthorized)
            }
        }
    }

    #[derive(Default)]
    pub struct StaticDirectory {
        pub local_clients: HashSet<String>,
        /// client_id -> (node_id, relay_url)
        pub remote_clients: HashMap<String, (String, String)>,
    }

    #[async_trait]
    impl NodeDirectory for StaticDirectory {
        async fn locate(&self, client_id: &str) -> Result<NodeLocation, NodeError> {
            if self.local_clients.contains(client_id) {
                Ok(NodeLocation::Local)
            } else if let Some((node_id, relay_url)) = self.remote_clients.get(client_id) {
                Ok(NodeLocation::Remote {
                    node_id: node_id.clone(),
                    relay_url: relay_url.clone(),
                })
            } else {
                Err(NodeError::UnknownRecipient)
            }
        }
    }
}

/// Wires up the in-memory mocks and starts listening on `127.0.0.1:8080`.
/// Not intended for production use — see [`mock`] for what each component
/// would look like backed by real infrastructure.
pub async fn example_main() -> std::io::Result<()> {
    use mock::*;

    let mut tokens = HashMap::new();
    tokens.insert("alice-token".to_string(), "alice".to_string());
    tokens.insert("bob-token".to_string(), "bob".to_string());

    let mut local_clients = std::collections::HashSet::new();
    local_clients.insert("alice".to_string());
    local_clients.insert("bob".to_string());

    let mut node_secrets = HashMap::new();
    node_secrets.insert("node-b".to_string(), "shared-secret-with-b".to_string());

    let state = AppState {
        store: Arc::new(InMemoryMessageStore::default()),
        client_auth: Arc::new(StaticTokenAuthenticator { tokens }),
        node_auth: Arc::new(StaticNodeAuthenticator {
            secrets: node_secrets,
        }),
        directory: Arc::new(StaticDirectory {
            local_clients,
            remote_clients: HashMap::new(),
        }),
        http_client: reqwest::Client::new(),
        config: Arc::new(NodeConfig {
            node_id: "node-a".to_string(),
            outbound_node_token: "shared-secret-with-b".to_string(),
        }),
    };

    run_node(state, "127.0.0.1:8080".parse().unwrap()).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::mock::*;
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt; // for `oneshot`

    fn test_state() -> AppState {
        let mut tokens = HashMap::new();
        tokens.insert("alice-token".to_string(), "alice".to_string());
        tokens.insert("bob-token".to_string(), "bob".to_string());

        let mut local_clients = std::collections::HashSet::new();
        local_clients.insert("alice".to_string());
        local_clients.insert("bob".to_string());

        let mut node_secrets = HashMap::new();
        node_secrets.insert("node-b".to_string(), "peer-secret".to_string());

        AppState {
            store: Arc::new(InMemoryMessageStore::default()),
            client_auth: Arc::new(StaticTokenAuthenticator { tokens }),
            node_auth: Arc::new(StaticNodeAuthenticator {
                secrets: node_secrets,
            }),
            directory: Arc::new(StaticDirectory {
                local_clients,
                remote_clients: HashMap::new(),
            }),
            http_client: reqwest::Client::new(),
            config: Arc::new(NodeConfig {
                node_id: "node-a".to_string(),
                outbound_node_token: "peer-secret".to_string(),
            }),
        }
    }

    #[tokio::test]
    async fn deposit_requires_authentication() {
        let app = build_router(test_state());

        let req = Request::builder()
            .method("POST")
            .uri("/api/client/messages")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"recipient_id":"bob","header":"aGVsbG8=","ciphertext":"aGVsbG8="}"#,
            ))
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn deposit_then_fetch_round_trip() {
        let app = build_router(test_state());

        let deposit_req = Request::builder()
            .method("POST")
            .uri("/api/client/messages")
            .header("content-type", "application/json")
            .header("authorization", "Bearer alice-token")
            .body(Body::from(
                r#"{"recipient_id":"bob","header":"aGVsbG8=","ciphertext":"aGVsbG8="}"#,
            ))
            .unwrap();
        let deposit_resp = app.clone().oneshot(deposit_req).await.unwrap();
        assert_eq!(deposit_resp.status(), StatusCode::OK);

        let fetch_req = Request::builder()
            .method("GET")
            .uri("/api/client/messages/bob")
            .header("authorization", "Bearer bob-token")
            .body(Body::empty())
            .unwrap();
        let fetch_resp = app.oneshot(fetch_req).await.unwrap();
        assert_eq!(fetch_resp.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(fetch_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let parsed: FetchMessagesResponse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.messages.len(), 1);
        assert_eq!(parsed.messages[0].sender_id, "alice");
    }

    #[tokio::test]
    async fn fetch_rejects_mismatched_client() {
        let app = build_router(test_state());

        let req = Request::builder()
            .method("GET")
            .uri("/api/client/messages/bob")
            .header("authorization", "Bearer alice-token")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn relay_requires_node_authentication() {
        let app = build_router(test_state());

        let envelope = EncryptedEnvelope {
            message_id: "id-1".into(),
            sender_id: "carol".into(),
            recipient_id: "bob".into(),
            header: "aGVsbG8=".into(),
            ciphertext: "aGVsbG8=".into(),
            timestamp: 0,
        };
        let body = serde_json::to_string(&RelayMessageRequest {
            envelope,
            origin_node_id: "node-b".into(),
        })
        .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/api/node/relay")
            .header("content-type", "application/json")
            .header("x-node-id", "node-b")
            .header("x-node-token", "wrong-secret")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn relay_accepts_valid_node_and_stores_locally() {
        let app = build_router(test_state());

        let envelope = EncryptedEnvelope {
            message_id: "id-2".into(),
            sender_id: "carol".into(),
            recipient_id: "bob".into(),
            header: "aGVsbG8=".into(),
            ciphertext: "aGVsbG8=".into(),
            timestamp: 0,
        };
        let body = serde_json::to_string(&RelayMessageRequest {
            envelope,
            origin_node_id: "node-b".into(),
        })
        .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/api/node/relay")
            .header("content-type", "application/json")
            .header("x-node-id", "node-b")
            .header("x-node-token", "peer-secret")
            .body(Body::from(body))
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }
}