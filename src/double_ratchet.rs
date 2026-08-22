use crate::{Data, HashKey, Header, HeaderError};
use crate::{HeaderKey, MessageKey, RootKey, SessionInit, SessionKeyStore, SessionTag, UserId};
use ed25519_dalek::VerifyingKey;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;
type HkdfSha256 = Hkdf<Sha256>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoubleRatchetError {
    NoSendingChain,
    ChainNotFound,
    SessionNotFound,
    MaxSkipExceeded,
    InvalidHeader,
    ChainInitFailed,
}
impl std::fmt::Display for DoubleRatchetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSendingChain => write!(f, "Uninitialized sending chain"),
            Self::ChainNotFound => write!(f, "Chain not found"),
            Self::SessionNotFound => write!(f, "Session not found"),
            Self::MaxSkipExceeded => write!(f, "Message count exceeds MAX_SKIP threshold"),
            Self::InvalidHeader => write!(f, "Invalid header"),
            Self::ChainInitFailed => write!(f, "Failed chain init"),
        }
    }
}
impl std::error::Error for DoubleRatchetError {}

const KEY_LENGTH: usize = 32;
const MAX_SKIP: u32 = 2000;
const SESSION_INFO: &[u8] = b"/freesignal/double_ratchet/v0.1";
const SESSION_TAG_INFO: &[u8] = b"/freesignal/double_ratchet/v0.1/tag";

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ChainKey(pub [u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionHeader {
    pub count: u32,
    pub previous: u32,
    pub public_key: PublicKey,
}

impl Header for SessionHeader {
    fn get_public_key(&self) -> PublicKey {
        self.public_key
    }

    fn to_slice(&self) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend_from_slice(&self.count.to_be_bytes());
        raw.extend_from_slice(&self.previous.to_be_bytes());
        raw.extend_from_slice(self.public_key.as_bytes());
        raw
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, HeaderError> {
        if bytes.len() != 40 {
            return Err(HeaderError());
        }

        let mut count = [0u8; 4];
        count.copy_from_slice(&bytes[0..4]);

        let mut previous = [0u8; 4];
        previous.copy_from_slice(&bytes[4..8]);

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&bytes[8..40]);

        Ok(Self {
            count: u32::from_be_bytes(count),
            previous: u32::from_be_bytes(previous),
            public_key: PublicKey::from(public_key),
        })
    }
}

pub const SESSION_DATA_SIZE: usize = 192 + CHAIN_SIZE * 2;

#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct SessionData {
    session_tag: SessionTag,
    #[zeroize(skip)]
    remote_identity: VerifyingKey,
    secret_key: StaticSecret,
    root_key: RootKey,
    header_key: Option<HeaderKey>,
    next_header_key: Option<HeaderKey>,
    sending_chain: Option<Chain>,
    receiving_chain: Option<Chain>,
}

impl Data<SESSION_DATA_SIZE> for SessionData {
    fn get_session_tag(&self) -> SessionTag {
        self.session_tag.clone()
    }

    fn to_bytes(&self) -> [u8; SESSION_DATA_SIZE] {
        let mut raw = [0u8; SESSION_DATA_SIZE];

        raw[..32].copy_from_slice(&self.session_tag.0);
        raw[32..64].copy_from_slice(self.remote_identity.as_bytes());
        raw[64..96].copy_from_slice(self.secret_key.as_bytes());
        raw[96..128].copy_from_slice(&self.root_key.0);
        raw[128..160].copy_from_slice(self.header_key.as_ref().map(|d| &d.0).unwrap_or(&[0u8; 32]));
        raw[160..192].copy_from_slice(
            self.next_header_key
                .as_ref()
                .map(|d| &d.0)
                .unwrap_or(&[0u8; 32]),
        );
        raw[192..192 + CHAIN_SIZE].copy_from_slice(
            &self
                .sending_chain
                .as_ref()
                .map(|d| d.to_bytes())
                .unwrap_or([0u8; CHAIN_SIZE]),
        );
        raw[192 + CHAIN_SIZE..].copy_from_slice(
            &self
                .receiving_chain
                .as_ref()
                .map(|d| d.to_bytes())
                .unwrap_or([0u8; CHAIN_SIZE]),
        );

        raw
    }

    fn from_bytes(bytes: &[u8; SESSION_DATA_SIZE]) -> Self {
        let mut session_tag = [0u8; 32];
        session_tag.copy_from_slice(&bytes[..32]);
        let mut remote_identity = [0u8; 32];
        remote_identity.copy_from_slice(&bytes[32..64]);
        let mut secret_key = [0u8; 32];
        secret_key.copy_from_slice(&bytes[64..96]);
        let mut root_key = [0u8; 32];
        root_key.copy_from_slice(&bytes[96..128]);
        let mut header_key = [0u8; 32];
        header_key.copy_from_slice(&bytes[128..160]);
        let mut next_header_key = [0u8; 32];
        next_header_key.copy_from_slice(&bytes[160..192]);

        Self {
            session_tag: SessionTag(session_tag),
            remote_identity: VerifyingKey::from_bytes(&remote_identity)
                .expect("Invalid SessionData bytes"),
            secret_key: StaticSecret::from(secret_key),
            root_key: RootKey(root_key),
            header_key: if header_key == [0u8; 32] {
                None
            } else {
                Some(HeaderKey(header_key))
            },
            next_header_key: if next_header_key == [0u8; 32] {
                None
            } else {
                Some(HeaderKey(next_header_key))
            },
            sending_chain: Chain::from_bytes(&bytes[192..192 + CHAIN_SIZE]),
            receiving_chain: Chain::from_bytes(&bytes[192 + CHAIN_SIZE..]),
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct Session<K: SessionKeyStore<SESSION_DATA_SIZE, SessionData>> {
    #[zeroize(skip)]
    pub keystore: K,
    current: SessionData,
    previous: Option<SessionData>,
}

impl<K: SessionKeyStore<SESSION_DATA_SIZE, SessionData>> Session<K> {
    pub fn new(init: &SessionInit, keystore: K) -> Session<K> {
        let mut session_tag = [0u8; KEY_LENGTH];
        let hkdf = HkdfSha256::new(Some(&[0u8; KEY_LENGTH]), init.root_key.0.as_ref());
        hkdf.expand(SESSION_TAG_INFO, &mut session_tag)
            .expect("HKDF failed");

        let mut session = Session {
            keystore,
            current: SessionData {
                session_tag: SessionTag(session_tag),
                remote_identity: init.remote_identity.clone(),
                root_key: init.root_key.clone(),
                header_key: init.header_key.clone(),
                next_header_key: init.next_header_key.clone(),
                secret_key: init
                    .secret_key
                    .clone()
                    .unwrap_or_else(|| StaticSecret::random_from_rng(rand_core::OsRng)),
                sending_chain: None,
                receiving_chain: None,
            },
            previous: None,
        };

        let public_key = session.get_public_key();
        session.keystore.set_hash_key(
            &HashKey(Sha256::digest(public_key.as_bytes()).into()),
            &SessionTag(session_tag),
        );

        session_tag.zeroize();

        if let Some(remote_key) = init.remote_key {
            session.current.sending_chain = Some(
                session
                    .init_chain(&remote_key, init.header_key.as_ref(), None)
                    .unwrap(),
            );
            session.current.header_key = None;
        }

        session.commit();

        session
    }

    pub fn get_session_tag(&self) -> SessionTag {
        self.current.session_tag.clone()
    }

    pub fn get_public_key(&self) -> PublicKey {
        PublicKey::from(&self.current.secret_key)
    }

    pub fn get_remote_hash_key(&self) -> Result<HashKey, DoubleRatchetError> {
        self.current
            .sending_chain
            .as_ref()
            .map(|c| HashKey(Sha256::digest(c.public_key.as_bytes()).into()))
            .ok_or(DoubleRatchetError::NoSendingChain)
    }

    fn init_chain(
        &mut self,
        remote_key: &PublicKey, // Rinominato per chiarezza
        header_key: Option<&HeaderKey>,
        previous_count: Option<u32>,
    ) -> Result<Chain, DoubleRatchetError> {
        let shared_key = self.current.secret_key.diffie_hellman(remote_key);

        let local_identity = self.keystore.get_verifying_key();
        let remote_identity = &self.current.remote_identity;

        let (key_1, key_2) = if local_identity.as_bytes() < remote_identity.as_bytes() {
            (local_identity.as_bytes(), remote_identity.as_bytes())
        } else {
            (remote_identity.as_bytes(), local_identity.as_bytes())
        };

        // 2. Costruiamo l'Associated Data (AD) sullo stack per evitare allocazioni.
        // Calcolo dimensione: 31 (SESSION_INFO) + 32 (SessionTag) + 32 (Id_1) + 32 (Id_2) = 127 byte
        let mut info_buf = [0u8; 128];
        let mut offset = 0;

        info_buf[offset..offset + SESSION_INFO.len()].copy_from_slice(SESSION_INFO);
        offset += SESSION_INFO.len();

        info_buf[offset..offset + 32].copy_from_slice(&self.current.session_tag.0);
        offset += 32;

        info_buf[offset..offset + 32].copy_from_slice(key_1);
        offset += 32;

        info_buf[offset..offset + 32].copy_from_slice(key_2);
        offset += 32;

        let mut hash_key = [0u8; KEY_LENGTH * 3];
        let hkdf = HkdfSha256::new(Some(&self.current.root_key.0), shared_key.as_bytes());
        hkdf.expand(&info_buf[..offset], &mut hash_key)
            .map_err(|_| DoubleRatchetError::ChainInitFailed)?;

        info_buf.zeroize();

        let mut root_val = [0u8; 32];
        let mut chain_val = [0u8; 32];
        let mut next_h_val = [0u8; 32];

        root_val.copy_from_slice(&hash_key[0..32]);
        chain_val.copy_from_slice(&hash_key[32..64]);
        next_h_val.copy_from_slice(&hash_key[64..96]);

        hash_key.zeroize();

        self.current.root_key = RootKey(root_val);

        let chain = Chain {
            count: 0,
            public_key: PublicKey::from(&self.current.secret_key),
            remote_key: *remote_key,
            chain_key: ChainKey(chain_val),
            next_header_key: HeaderKey(next_h_val),
            header_key: header_key.cloned(),
            previous_count: previous_count.unwrap_or(0),
        };

        Ok(chain)
    }

    pub fn commit(&mut self) {
        self.previous = Some(self.current.clone());
        self.keystore.set_data(&self.current);
        self.keystore.commit();
    }

    pub fn rollback(&mut self) -> bool {
        if self.previous.is_none() {
            return false;
        }
        if self.keystore.rollback() {
            if let Some(backup) = self.previous.take() {
                self.current = backup;
                return true;
            }
        }
        false
    }

    pub fn get_header_key(&self) -> Option<HeaderKey> {
        self.current.header_key.clone().or(self
            .current
            .sending_chain
            .as_ref()
            .map(|d| d.header_key.clone())
            .flatten())
    }

    pub fn get_sending_key(
        &mut self,
    ) -> Result<(MessageKey, SessionHeader, Option<HeaderKey>), DoubleRatchetError> {
        let chain = self
            .current
            .sending_chain
            .as_mut()
            .ok_or(DoubleRatchetError::NoSendingChain)?;

        let msg_key = chain.get_key();

        let header_key: Option<HeaderKey> =
            self.current.header_key.clone().or(chain.header_key.clone());

        Ok((msg_key, chain.get_header(), header_key))
    }

    pub fn get_receiving_key(
        &mut self,
        header: &SessionHeader,
    ) -> Result<MessageKey, DoubleRatchetError> {
        let session_tag = self.get_session_tag();

        if let Some(key) = self.keystore.get_previous_keys(&session_tag) {
            return Ok(key);
        }

        let is_new_remote_key = match &self.current.receiving_chain {
            Some(chain) => {
                chain
                    .remote_key
                    .as_bytes()
                    .ct_eq(header.get_public_key().as_bytes())
                    .unwrap_u8()
                    == 0
            }
            None => true,
        };

        if is_new_remote_key {
            let previous_rc_count = self.current.receiving_chain.as_ref().map_or(0, |c| c.count);
            if header.previous < previous_rc_count {
                return Err(DoubleRatchetError::InvalidHeader);
            }
            if header.previous.saturating_sub(previous_rc_count) > MAX_SKIP {
                return Err(DoubleRatchetError::MaxSkipExceeded);
            }
            if header.count > MAX_SKIP {
                return Err(DoubleRatchetError::MaxSkipExceeded);
            }
        } else {
            let current_rc_count = self.current.receiving_chain.as_ref().map_or(0, |c| c.count);
            if header.count < current_rc_count {
                return Err(DoubleRatchetError::ChainNotFound);
            }
            if header.count.saturating_sub(current_rc_count) > MAX_SKIP {
                return Err(DoubleRatchetError::MaxSkipExceeded);
            }
        }

        if is_new_remote_key {
            let old_receiving_chain = self.current.receiving_chain.clone();
            let mut previous_count = old_receiving_chain.as_ref().map(|c| c.count);
            let mut rc_header_key: Option<HeaderKey> = self.current.next_header_key.clone();

            if let Some(mut rc) = old_receiving_chain {
                while rc.count < header.previous {
                    let key = rc.get_key();
                    self.keystore.set_previous_keys(&session_tag, &key);
                }
                previous_count = Some(rc.count);

                rc_header_key = rc_header_key.or(Some(rc.next_header_key.clone()));
            }

            let new_rc = self.init_chain(
                &header.get_public_key(),
                rc_header_key.as_ref(),
                previous_count,
            )?;
            self.current.receiving_chain = Some(new_rc.clone());

            self.current.secret_key = StaticSecret::random_from_rng(rand_core::OsRng);
            let new_pub_key = self.get_public_key();
            let hash: [u8; 32] = Sha256::digest(new_pub_key.as_bytes()).into();

            if let Some(old_nhk) = &rc_header_key {
                self.keystore
                    .set_header_key(&HashKey(hash.clone()), old_nhk);
            }

            self.keystore.set_hash_key(&HashKey(hash), &session_tag);

            if self.current.next_header_key.is_some() {
                self.current.next_header_key = None;
            }

            let old_sending_chain = self.current.sending_chain.clone();
            let sending_chain_count = old_sending_chain.as_ref().map(|c| c.count).unwrap_or(0);
            let sc_next_hk = old_sending_chain.map(|c| c.next_header_key.clone());
            let sc_header_key = self.current.header_key.clone().or(sc_next_hk);

            self.current.sending_chain = Some(self.init_chain(
                &header.get_public_key(),
                sc_header_key.as_ref(),
                Some(sending_chain_count),
            )?);

            if self.current.header_key.is_some() {
                self.current.header_key = None;
            }
        }

        let receiving_chain = self.current.receiving_chain.as_mut().unwrap();

        let mut final_key: Option<MessageKey> = None;
        while receiving_chain.count < header.count {
            let key = receiving_chain.get_key();
            if receiving_chain.count == header.count {
                final_key = Some(key);
            } else {
                self.keystore.set_previous_keys(&session_tag, &key);
            }
        }

        final_key.ok_or(DoubleRatchetError::ChainNotFound)
    }

    pub fn from(session_data: &SessionData, keystore: K) -> Self {
        Self {
            keystore,
            current: session_data.clone(),
            previous: None,
        }
    }

    pub fn from_header(
        bytes: &[u8],
        keystore: K,
    ) -> Result<(Self, SessionHeader), DoubleRatchetError> {
        let mut hash_key = [0u8; 32];
        hash_key.copy_from_slice(&bytes[..32]);

        let header_key = keystore
            .get_header_key(&HashKey(hash_key))
            .ok_or(DoubleRatchetError::SessionNotFound)?;

        let header = if bytes.len() == 100 {
            let encrypted_bytes = bytes[32..]
                .try_into()
                .map_err(|_| DoubleRatchetError::InvalidHeader)?;
            header_key
                .decrypt_header(encrypted_bytes)
                .map_err(|_| DoubleRatchetError::InvalidHeader)?
        } else if bytes.len() == 72 {
            SessionHeader::from_bytes(
                bytes[32..]
                    .try_into()
                    .map_err(|_| DoubleRatchetError::InvalidHeader)?,
            )
            .map_err(|_| DoubleRatchetError::InvalidHeader)?
        } else {
            return Err(DoubleRatchetError::InvalidHeader);
        };

        let session_data = keystore
            .get_data_by_hash(&HashKey(hash_key)) // Usa il prefisso originale
            .ok_or(DoubleRatchetError::SessionNotFound)?;

        Ok((Session::from(&session_data, keystore), header))
    }

    fn has_skipped_keys(&self) -> bool {
        self.keystore.has_previous_keys()
    }
}

const CHAIN_SIZE: usize = 168;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Chain {
    count: u32,
    previous_count: u32,
    public_key: PublicKey,
    remote_key: PublicKey,
    header_key: Option<HeaderKey>,
    next_header_key: HeaderKey,
    chain_key: ChainKey,
}

impl Chain {
    fn get_key(&mut self) -> MessageKey {
        let mut mac_msg = HmacSha256::new_from_slice(&self.chain_key.0)
            .expect("L'HMAC accetta chiavi di qualsiasi dimensione");
        mac_msg.update(&[0x01]);
        let msg_key_bytes: [u8; 32] = mac_msg.finalize().into_bytes().into();

        let mut mac_chain = HmacSha256::new_from_slice(&self.chain_key.0)
            .expect("L'HMAC accetta chiavi di qualsiasi dimensione");
        mac_chain.update(&[0x02]);
        let next_chain_key_bytes: [u8; 32] = mac_chain.finalize().into_bytes().into();

        self.chain_key.0.zeroize();
        self.chain_key.0.copy_from_slice(&next_chain_key_bytes);

        self.count += 1;

        MessageKey(msg_key_bytes)
    }

    fn get_header(&self) -> SessionHeader {
        SessionHeader {
            count: self.count,
            previous: self.previous_count,
            public_key: self.public_key,
        }
    }

    fn to_bytes(&self) -> [u8; CHAIN_SIZE] {
        let mut raw = [0u8; CHAIN_SIZE];
        raw[..4].copy_from_slice(&self.count.to_be_bytes());
        raw[4..8].copy_from_slice(&self.previous_count.to_be_bytes());
        raw[8..40].copy_from_slice(self.public_key.as_bytes());
        raw[40..72].copy_from_slice(self.remote_key.as_bytes());
        raw[72..104].copy_from_slice(self.header_key.as_ref().map(|d| &d.0).unwrap_or(&[0u8; 32]));
        raw[104..136].copy_from_slice(&self.next_header_key.0);
        raw[136..].copy_from_slice(&self.chain_key.0);
        raw
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != CHAIN_SIZE {
            None
        } else if bytes == [0u8; CHAIN_SIZE] {
            None
        } else {
            let mut count = [0u8; 4];
            count.copy_from_slice(&bytes[..4]);
            let mut previous_count = [0u8; 4];
            previous_count.copy_from_slice(&bytes[4..8]);
            let mut public_key = [0u8; 32];
            public_key.copy_from_slice(&bytes[8..40]);
            let mut remote_key = [0u8; 32];
            remote_key.copy_from_slice(&bytes[40..72]);
            let mut header_key = [0u8; 32];
            header_key.copy_from_slice(&bytes[72..104]);
            let mut next_header_key = [0u8; 32];
            next_header_key.copy_from_slice(&bytes[104..136]);
            let mut chain_key = [0u8; 32];
            chain_key.copy_from_slice(&bytes[136..]);

            Some(Self {
                count: u32::from_be_bytes(count),
                previous_count: u32::from_be_bytes(previous_count),
                public_key: PublicKey::from(public_key),
                remote_key: PublicKey::from(remote_key),
                header_key: if header_key == [0u8; 32] {
                    None
                } else {
                    Some(HeaderKey(header_key))
                },
                next_header_key: HeaderKey(next_header_key),
                chain_key: ChainKey(chain_key),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HashKey;
    use ed25519_dalek::SigningKey;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    fn gen_identity() -> VerifyingKey {
        let secret = StaticSecret::random_from_rng(rand_core::OsRng);
        let signing_key = SigningKey::from_bytes(&secret.to_bytes());
        signing_key.verifying_key()
    }

    #[derive(Clone)]
    struct MemoryKeystore {
        local_identity: VerifyingKey,
        header_keys: Rc<RefCell<HashMap<HashKey, HeaderKey>>>,
        previous_keys: Rc<RefCell<HashMap<SessionTag, MessageKey>>>,
        session_data: Rc<RefCell<HashMap<SessionTag, SessionData>>>,
        session_tag_map: Rc<RefCell<HashMap<HashKey, SessionTag>>>,
    }

    impl MemoryKeystore {
        fn new(local_identity: VerifyingKey) -> Self {
            Self {
                local_identity,
                header_keys: Rc::new(RefCell::new(HashMap::new())),
                previous_keys: Rc::new(RefCell::new(HashMap::new())),
                session_data: Rc::new(RefCell::new(HashMap::new())),
                session_tag_map: Rc::new(RefCell::new(HashMap::new())),
            }
        }
    }

    impl SessionKeyStore<{ SESSION_DATA_SIZE }, SessionData> for MemoryKeystore {
        fn get_verifying_key(&self) -> VerifyingKey {
            self.local_identity
        }

        fn set_header_key(&self, key: &HashKey, value: &HeaderKey) {
            self.header_keys
                .borrow_mut()
                .insert(key.clone(), value.clone());
        }
        fn get_header_key(&self, key: &HashKey) -> Option<HeaderKey> {
            self.header_keys.borrow().get(key).cloned()
        }
        fn set_previous_keys(&self, key: &SessionTag, value: &MessageKey) {
            self.previous_keys
                .borrow_mut()
                .insert(key.clone(), value.clone());
        }
        fn get_previous_keys(&self, key: &SessionTag) -> Option<MessageKey> {
            self.previous_keys.borrow_mut().remove(key)
        }
        fn del_previous_keys(&self, hash: Option<&SessionTag>) -> bool {
            if let Some(h) = hash {
                self.previous_keys.borrow_mut().remove(h).is_some()
            } else {
                self.previous_keys.borrow_mut().clear();
                true
            }
        }
        fn has_previous_keys(&self) -> bool {
            !self.previous_keys.borrow().is_empty()
        }
        fn set_data(&self, session: &SessionData) {
            self.session_data
                .borrow_mut()
                .insert(session.get_session_tag(), session.clone());
        }
        fn set_hash_key(&self, hash_key: &HashKey, session_tag: &SessionTag) {
            self.session_tag_map
                .borrow_mut()
                .insert(hash_key.clone(), session_tag.clone());
        }
        fn get_data_by_hash(&self, hash_key: &HashKey) -> Option<SessionData> {
            let tag = self.session_tag_map.borrow().get(&hash_key).cloned()?;
            self.get_data_by_tag(&tag)
        }
        fn get_data_by_tag(&self, session_tag: &SessionTag) -> Option<SessionData> {
            self.session_data.borrow().get(&session_tag).cloned()
        }
        fn commit(&self) {}
        fn rollback(&self) -> bool {
            true
        }
    }

    #[test]
    fn test_session_message_exchange() {
        let shared_root_key = RootKey([42u8; 32]);
        let bob_identity = gen_identity();
        let alice_identity = gen_identity();

        let bob_keystore = MemoryKeystore::new(bob_identity);
        let bob_init = SessionInit {
            remote_identity: alice_identity, // Corretto rispetto a user_id
            remote_key: None,
            root_key: shared_root_key.clone(),
            secret_key: None,
            header_key: None,
            next_header_key: None,
        };
        let mut bob_session = Session::new(&bob_init, bob_keystore);
        let bob_public_key = PublicKey::from(&bob_session.current.secret_key);

        let alice_keystore = MemoryKeystore::new(alice_identity);
        let alice_init = SessionInit {
            remote_identity: bob_identity, // Corretto
            remote_key: Some(bob_public_key),
            secret_key: None,
            root_key: shared_root_key,
            header_key: None,
            next_header_key: None,
        };
        let mut alice_session = Session::new(&alice_init, alice_keystore);

        let (alice_msg_key_1, header_1, _) = alice_session.get_sending_key().unwrap();

        let bob_msg_key_1 = bob_session.get_receiving_key(&header_1).unwrap();

        assert_eq!(
            alice_msg_key_1.0, bob_msg_key_1.0,
            "The keys of the first message do not match"
        );

        assert_eq!(header_1.count, 1);

        let (alice_msg_key_2, header_2, _) = alice_session.get_sending_key().unwrap();
        let bob_msg_key_2 = bob_session.get_receiving_key(&header_2).unwrap();

        assert_eq!(
            alice_msg_key_2.0, bob_msg_key_2.0,
            "The keys of the second message do not match"
        );

        assert_eq!(header_2.count, 2);

        let (bob_reply_key_1, header_reply_1, _) = bob_session.get_sending_key().unwrap();
        let alice_reply_key_1 = alice_session.get_receiving_key(&header_reply_1).unwrap();

        assert_eq!(
            bob_reply_key_1.0, alice_reply_key_1.0,
            "The keys of Bob's response do not match"
        );

        assert_eq!(header_reply_1.count, 1);
        assert_eq!(header_reply_1.previous, 0);
    }

    #[test]
    fn test_skipped_key_is_single_use() {
        let shared_root_key = RootKey([7u8; 32]);
        let bob_identity = gen_identity();
        let alice_identity = gen_identity();

        let bob_keystore = MemoryKeystore::new(bob_identity);
        let bob_init = SessionInit {
            remote_identity: alice_identity,
            remote_key: None,
            secret_key: None,
            root_key: shared_root_key.clone(),
            header_key: None,
            next_header_key: None,
        };
        let mut bob_session = Session::new(&bob_init, bob_keystore);
        let bob_public_key = PublicKey::from(&bob_session.current.secret_key);

        let alice_keystore = MemoryKeystore::new(alice_identity);
        let alice_init = SessionInit {
            remote_identity: bob_identity,
            remote_key: Some(bob_public_key),
            secret_key: None,
            root_key: shared_root_key,
            header_key: None,
            next_header_key: None,
        };
        let mut alice_session = Session::new(&alice_init, alice_keystore);

        let (_alice_key_1, header_1, _) = alice_session.get_sending_key().unwrap();
        let (alice_key_2, header_2, _) = alice_session.get_sending_key().unwrap();

        let bob_key_2 = bob_session.get_receiving_key(&header_2).unwrap();
        assert_eq!(alice_key_2.0, bob_key_2.0);
        assert!(bob_session.has_skipped_keys());

        let bob_key_1_first = bob_session.get_receiving_key(&header_1).unwrap();
        assert!(!bob_session.has_skipped_keys());

        let bob_key_1_second = bob_session.get_receiving_key(&header_1);
        assert!(
            bob_key_1_second.is_err(),
            "The skipped message key must be used only once"
        );
        let _ = bob_key_1_first;
    }

    #[test]
    fn test_session_get_sending_key_header_key_retrieval() {
        let shared_root_key = RootKey([88u8; 32]);
        let alice_identity = gen_identity();
        let bob_identity = gen_identity();
        let keystore = MemoryKeystore::new(alice_identity);

        let bob_secret = StaticSecret::random_from_rng(rand_core::OsRng);
        let bob_pubkey = PublicKey::from(&bob_secret);
        let initial_header_key = HeaderKey([0x11; 32]);

        let init = SessionInit {
            remote_identity: bob_identity,
            remote_key: Some(bob_pubkey),
            root_key: shared_root_key,
            secret_key: Some(bob_secret),
            header_key: Some(initial_header_key.clone()),
            next_header_key: None,
        };

        let mut session = Session::new(&init, keystore);
        let (msg_key, header, header_key) = session.get_sending_key().unwrap();

        assert_eq!(header.count, 1);
        assert_eq!(header_key, Some(initial_header_key));
        assert_ne!(msg_key.0, [0u8; 32]);
    }

    #[test]
    fn test_double_ratchet_errors_display() {
        assert_eq!(
            format!("{}", DoubleRatchetError::NoSendingChain),
            "Uninitialized sending chain"
        );
        assert_eq!(
            format!("{}", DoubleRatchetError::MaxSkipExceeded),
            "Message count exceeds MAX_SKIP threshold"
        );
        assert_eq!(
            format!("{}", DoubleRatchetError::InvalidHeader),
            "Invalid header"
        );
    }

    #[test]
    fn test_session_header_serialization() {
        let header = SessionHeader {
            count: 42,
            previous: 12,
            public_key: PublicKey::from(&StaticSecret::random_from_rng(rand_core::OsRng)),
        };

        let bytes = header.to_slice();
        let decoded = SessionHeader::from_bytes(&bytes).unwrap();

        assert_eq!(header.count, decoded.count);
        assert_eq!(header.previous, decoded.previous);
        assert_eq!(header.public_key.as_bytes(), decoded.public_key.as_bytes());
    }

    #[test]
    fn test_session_data_serialization_roundtrip() {
        let bob_identity = gen_identity();
        let alice_identity = gen_identity();
        let bob_keystore = MemoryKeystore::new(bob_identity);
        let bob_init = SessionInit {
            remote_identity: alice_identity,
            remote_key: None,
            root_key: RootKey([2u8; 32]),
            secret_key: None,
            header_key: Some(HeaderKey([3u8; 32])),
            next_header_key: None,
        };
        let mut session = Session::new(&bob_init, bob_keystore);

        let fake_remote = PublicKey::from(&StaticSecret::random_from_rng(rand_core::OsRng));
        session.current.sending_chain =
            Some(session.init_chain(&fake_remote, None, Some(5)).unwrap());

        let bytes = session.current.to_bytes();
        let decoded = SessionData::from_bytes(&bytes);

        assert_eq!(session.current.session_tag.0, decoded.session_tag.0);
        assert_eq!(
            session.current.remote_identity.as_bytes(),
            decoded.remote_identity.as_bytes()
        ); // Risolve il bug su user_id
        assert_eq!(
            session.current.secret_key.to_bytes(),
            decoded.secret_key.to_bytes()
        );
        assert_eq!(session.current.root_key.0, decoded.root_key.0);
        assert_eq!(session.current.header_key, decoded.header_key);
        assert_eq!(session.current.next_header_key, decoded.next_header_key);
        assert!(decoded.sending_chain.is_some());
        assert_eq!(decoded.sending_chain.clone().unwrap().previous_count, 5);
    }

    #[test]
    fn test_max_skip_exceeded_rejection() {
        let shared_root_key = RootKey([7u8; 32]);
        let bob_identity = gen_identity();
        let alice_identity = gen_identity();
        let bob_keystore = MemoryKeystore::new(bob_identity);
        let bob_init = SessionInit {
            remote_identity: alice_identity,
            remote_key: None,
            secret_key: None,
            root_key: shared_root_key,
            header_key: None,
            next_header_key: None,
        };
        let mut bob_session = Session::new(&bob_init, bob_keystore);

        let fake_header = SessionHeader {
            count: super::MAX_SKIP + 1, // 2001
            previous: 0,
            public_key: PublicKey::from(&StaticSecret::random_from_rng(rand_core::OsRng)),
        };

        let result = bob_session.get_receiving_key(&fake_header);
        assert_eq!(result.err(), Some(DoubleRatchetError::MaxSkipExceeded));
    }

    #[test]
    fn test_invalid_header_past_previous_count() {
        let shared_root_key = RootKey([8u8; 32]);
        let bob_identity = gen_identity();
        let alice_identity = gen_identity();
        let bob_keystore = MemoryKeystore::new(bob_identity);
        let bob_init = SessionInit {
            remote_identity: alice_identity,
            remote_key: None,
            secret_key: None,
            root_key: shared_root_key.clone(),
            header_key: None,
            next_header_key: None,
        };
        let mut bob_session = Session::new(&bob_init, bob_keystore.clone());

        let old_remote = PublicKey::from(&StaticSecret::random_from_rng(rand_core::OsRng));
        let mut mock_rc = bob_session.init_chain(&old_remote, None, None).unwrap();
        mock_rc.count = 50;
        bob_session.current.receiving_chain = Some(mock_rc);

        let new_remote = PublicKey::from(&StaticSecret::random_from_rng(rand_core::OsRng));
        let bad_header = SessionHeader {
            count: 10,
            previous: 10,
            public_key: new_remote,
        };

        let result = bob_session.get_receiving_key(&bad_header);
        assert_eq!(result.err(), Some(DoubleRatchetError::InvalidHeader));
    }

    #[test]
    fn test_session_rollback() {
        let bob_identity = gen_identity();
        let alice_identity = gen_identity();
        let bob_keystore = MemoryKeystore::new(bob_identity);
        let init = SessionInit {
            remote_identity: alice_identity,
            remote_key: None,
            root_key: RootKey([2u8; 32]),
            secret_key: None,
            header_key: None,
            next_header_key: None,
        };
        let mut session = Session::new(&init, bob_keystore);

        session.commit();
        let initial_root = session.current.root_key.clone();

        let fake_remote = PublicKey::from(&StaticSecret::random_from_rng(rand_core::OsRng));
        let new_chain = session.init_chain(&fake_remote, None, None).unwrap();
        session.current.receiving_chain = Some(new_chain);

        assert_ne!(session.current.root_key.0, initial_root.0);

        let rolled_back = session.rollback();
        assert!(
            rolled_back,
            "Il rollback dovrebbe avere successo se esiste uno stato precedente"
        );

        assert_eq!(
            session.current.root_key.0, initial_root.0,
            "La sessione deve tornare allo stato precedente"
        );

        assert!(
            !session.rollback(),
            "Non è possibile fare un doppio rollback consecutivo"
        );
    }
}
