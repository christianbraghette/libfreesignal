use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

mod double_ratchet;
mod x3dh;

#[derive(Clone, Zeroize, ZeroizeOnDrop, Eq, Hash, PartialEq, Debug)]
pub struct UserId(pub [u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MessageKey(pub [u8; 32]);

pub type KeyHash = [u8; 32];

#[derive(Clone, Zeroize, ZeroizeOnDrop, Eq, Hash, PartialEq)]
pub struct SessionTag(pub [u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootKey(pub [u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop, Eq, Hash, PartialEq, Debug)]
pub struct HeaderKey(pub [u8; 32]);

const KEY_LENGTH: usize = 32;
const PUBLIC_ID_INFO: &[u8] = b"freesignal/user_id/v0.1";

#[derive(Clone)]
pub struct PublicIdentity(pub VerifyingKey);

impl PublicIdentity {
    pub fn get_user_id(&self) -> UserId {
        let mut user_id = [0u8; KEY_LENGTH];
        let hkdf = Hkdf::<Sha256>::new(Some(&[0u8; KEY_LENGTH]), self.0.as_bytes());
        hkdf.expand(PUBLIC_ID_INFO, &mut user_id)
            .expect("HKDF failed");
        UserId(user_id)
    }

    pub fn get_key(&self) -> VerifyingKey {
        self.0
    }

    pub fn to_public_key(&self) -> PublicKey {
        PublicKey::from(self.0.to_montgomery().to_bytes())
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderEncryptionError();

impl std::fmt::Display for HeaderEncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Failed crypto operation")
    }
}

impl std::error::Error for HeaderEncryptionError {}

pub trait Header {
    fn get_public_key(&self) -> PublicKey;
    fn encrypt(&self, header_key: &HeaderKey) -> Result<[u8; 96], HeaderEncryptionError>;
    fn to_bytes(&self) -> [u8; 68];
    fn from_bytes(bytes: &[u8; 68]) -> Self;

    fn decrypt<K: HeaderKeyStore>(
        encrypted_bytes: &[u8; 96],
        keystore: &K,
    ) -> Result<Self, HeaderEncryptionError>
    where
        Self: Sized;
}

pub trait Data<const N: usize> {
    fn get_session_tag(&self) -> SessionTag;
    fn to_bytes(&self) -> [u8; N];
    fn from_bytes(bytes: &[u8; N]) -> Self;
}

#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct SessionInit {
    pub user_id: UserId,
    pub remote_key: Option<PublicKey>,
    pub secret_key: Option<StaticSecret>,
    pub root_key: RootKey,
    pub header_key: Option<HeaderKey>,
    pub next_header_key: Option<HeaderKey>,
}

pub type HashKey = [u8; 32];

pub trait HeaderKeyStore {
    fn set_header_key(&self, hash_key: &HashKey, value: &HeaderKey);
    fn get_header_key(&self, hash_key: &HashKey) -> Option<HeaderKey>;
}

pub trait SessionKeyStore<const N: usize, D: Data<N>> {
    fn set_data(&self, session: &D);
    fn set_public_key(&self, public_key: &PublicKey, session_tag: &SessionTag);
    fn get_data_by_key(&self, public_key: &PublicKey) -> Option<D>;
    fn get_data_by_tag(&self, session_tag: &SessionTag) -> Option<D>;

    fn set_previous_keys(&self, session_tag: &SessionTag, value: &MessageKey);
    fn get_previous_keys(&self, session_tag: &SessionTag) -> Option<MessageKey>;
    fn del_previous_keys(&self, session_tag: Option<&SessionTag>) -> bool;
    fn has_previous_keys(&self) -> bool;

    fn commit(&self);
    fn rollback(&self) -> bool;
}

pub trait KeyExchangeStore {
    fn get_signing_key(&self) -> SigningKey;
    fn store_pre_key(&self, prekey_hash: &[u8], prekey: &StaticSecret);
    fn load_pre_key(&self, prekey_hash: &[u8]) -> Option<StaticSecret>;
    fn remove_pre_key(&self, prekey_hash: &[u8]) -> bool;
}
