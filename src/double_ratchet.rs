use crate::{Data, HashKey, Header, HeaderError};
use crate::{HeaderKey, MessageKey, SessionInit, SessionKeyStore, SessionTag};
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

#[derive(Clone, Zeroize, ZeroizeOnDrop, Eq, PartialEq)]
pub struct ChainKey {
    remote_key: PublicKey,
    key: [u8; 32],
    count: u32,
    prev: u32,
}

impl ChainKey {
    pub fn new(bytes: [u8; 32], prev: u32, remote_key: PublicKey) -> Self {
        Self {
            remote_key,
            key: bytes,
            count: 0,
            prev,
        }
    }

    pub fn expand(&mut self) -> MessageKey {
        let mut mac_msg =
            HmacSha256::new_from_slice(&self.key).expect("HMAC accepts keys of any size");
        mac_msg.update(&[0x01]);
        let msg_key_bytes: [u8; 32] = mac_msg.finalize().into_bytes().into();

        let mut mac_chain =
            HmacSha256::new_from_slice(&self.key).expect("HMAC accepts keys of any size");
        mac_chain.update(&[0x02]);
        let next_chain_key_bytes: [u8; 32] = mac_chain.finalize().into_bytes().into();

        self.key.zeroize();
        self.key.copy_from_slice(&next_chain_key_bytes);

        self.count += 1;

        MessageKey(msg_key_bytes)
    }

    pub fn compare(&self, remote_key: &PublicKey) -> bool {
        self.remote_key
            .as_bytes()
            .ct_eq(remote_key.as_bytes())
            .unwrap_u8()
            == 0
    }

    pub fn header(&self, public_key: PublicKey) -> SessionHeader {
        SessionHeader {
            count: self.count,
            previous: self.prev,
            public_key,
        }
    }

    pub fn to_bytes(&self) -> [u8; 72] {
        let mut raw = [0u8; 72];
        raw[..32].copy_from_slice(self.remote_key.as_bytes());
        raw[32..64].copy_from_slice(&self.key);
        raw[64..68].copy_from_slice(&self.count.to_be_bytes());
        raw[68..].copy_from_slice(&self.prev.to_be_bytes());

        raw
    }

    pub fn from(bytes: &[u8; 72]) -> Self {
        let mut remote_key = [0u8; 32];
        remote_key.copy_from_slice(&bytes[..32]);

        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes[32..64]);

        let mut count = [0u8; 4];
        count.copy_from_slice(&bytes[64..68]);

        let mut prev = [0u8; 4];
        prev.copy_from_slice(&bytes[68..]);

        Self {
            remote_key: PublicKey::from(remote_key),
            key,
            count: u32::from_be_bytes(count),
            prev: u32::from_be_bytes(prev),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 72 && bytes != [0u8; 72] {
            let mut raw = [0u8; 72];
            raw.copy_from_slice(bytes);
            Some(Self::from(&raw))
        } else {
            None
        }
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootKey {
    secret_key: StaticSecret,
    key: [u8; 32],
}

impl RootKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self {
            secret_key: StaticSecret::random_from_rng(rand_core::OsRng),
            key: bytes,
        }
    }

    pub fn update(&mut self) {
        self.secret_key = StaticSecret::random_from_rng(rand_core::OsRng);
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.secret_key)
    }

    pub fn expand(
        &mut self,
        remote_key: PublicKey,
        aad: Option<&[u8]>,
    ) -> Result<(ChainKey, HeaderKey), DoubleRatchetError> {
        let shared_key = self.secret_key.diffie_hellman(&remote_key);

        let mut hash_key = [0u8; KEY_LENGTH * 3];
        let hkdf = HkdfSha256::new(Some(&self.key), shared_key.as_bytes());
        hkdf.expand(aad.unwrap_or(&[0u8; 32]), &mut hash_key)
            .map_err(|_| DoubleRatchetError::ChainInitFailed)?;

        self.key.zeroize();
        self.key.copy_from_slice(&hash_key[0..32]);

        let mut chain_val = [0u8; 32];
        chain_val.copy_from_slice(&hash_key[32..64]);

        let mut hk_val = [0u8; 32];
        hk_val.copy_from_slice(&hash_key[64..96]);

        hash_key.zeroize();

        Ok((ChainKey::new(chain_val, 0, remote_key), HeaderKey(hk_val)))
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut raw = [0u8; 64];
        raw[..32].copy_from_slice(self.secret_key.as_bytes());
        raw[32..].copy_from_slice(&self.key);

        raw
    }

    pub fn from(bytes: &[u8; 64]) -> Self {
        let mut secret_key = [0u8; 32];
        secret_key.copy_from_slice(&bytes[..32]);

        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes[32..]);

        Self {
            secret_key: StaticSecret::from(secret_key),
            key,
        }
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop, Eq, PartialEq, Default, Debug)]
struct HeaderKeys {
    curr: Option<HeaderKey>,
    next: Option<HeaderKey>,
}

impl HeaderKeys {
    pub fn new(next_header_key: HeaderKey) -> Self {
        Self {
            curr: None,
            next: Some(next_header_key),
        }
    }

    pub fn header_key(&self) -> Option<HeaderKey> {
        self.curr.clone()
    }

    pub fn update(&mut self, header_key: HeaderKey) {
        self.curr.zeroize();
        self.curr = self.next.take();
        self.next = Some(header_key);
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        let mut raw = [0u8; 64];
        if let Some(ref curr) = self.curr {
            raw[..32].copy_from_slice(&curr.0);
        }
        if let Some(ref next) = self.next {
            raw[32..].copy_from_slice(&next.0);
        }
        raw
    }

    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let mut curr = [0u8; 32];
        curr.copy_from_slice(&bytes[..32]);
        let mut next = [0u8; 32];
        next.copy_from_slice(&bytes[32..]);

        Self {
            curr: if curr == [0u8; 32] {
                None
            } else {
                Some(HeaderKey(curr))
            },
            next: if next == [0u8; 32] {
                None
            } else {
                Some(HeaderKey(next))
            },
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct SessionData {
    session_tag: SessionTag,
    #[zeroize(skip)]
    remote_identity: VerifyingKey,
    root_key: RootKey,
    sending_header_keys: HeaderKeys,
    receiving_header_keys: HeaderKeys,
    sending_chain_key: Option<ChainKey>,
    receiving_chain_key: Option<ChainKey>,
}

const SESSION_DATA_SIZE: usize = 400;

impl Data for SessionData {
    fn get_session_tag(&self) -> SessionTag {
        self.session_tag.clone()
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(SESSION_DATA_SIZE);

        raw.extend_from_slice(&self.session_tag.0);
        raw.extend_from_slice(self.remote_identity.as_bytes());
        raw.extend_from_slice(&self.root_key.to_bytes());
        raw.extend_from_slice(&self.sending_header_keys.to_bytes());
        raw.extend_from_slice(&self.receiving_header_keys.to_bytes());
        raw.extend_from_slice(
            &self
                .sending_chain_key
                .as_ref()
                .map(|d| d.to_bytes())
                .unwrap_or([0u8; 72]),
        );
        raw.extend_from_slice(
            &self
                .receiving_chain_key
                .as_ref()
                .map(|d| d.to_bytes())
                .unwrap_or([0u8; 72]),
        );

        raw
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(
            bytes.len(),
            SESSION_DATA_SIZE,
            "Invalid SessionData buffer size"
        );

        let mut session_tag = [0u8; 32];
        session_tag.copy_from_slice(&bytes[0..32]);

        let mut remote_identity = [0u8; 32];
        remote_identity.copy_from_slice(&bytes[32..64]);

        let mut root_key = [0u8; 64];
        root_key.copy_from_slice(&bytes[64..128]);

        let mut sending_hk = [0u8; 64];
        sending_hk.copy_from_slice(&bytes[128..192]);

        let mut receiving_hk = [0u8; 64];
        receiving_hk.copy_from_slice(&bytes[192..256]);

        Self {
            session_tag: SessionTag(session_tag),
            remote_identity: VerifyingKey::from_bytes(&remote_identity)
                .expect("Invalid SessionData bytes"),
            root_key: RootKey::from(&root_key),
            sending_header_keys: HeaderKeys::from_bytes(&sending_hk),
            receiving_header_keys: HeaderKeys::from_bytes(&receiving_hk),
            sending_chain_key: ChainKey::from_bytes(&bytes[256..328]),
            receiving_chain_key: ChainKey::from_bytes(&bytes[328..400]),
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct Session<K: SessionKeyStore<SessionData>> {
    #[zeroize(skip)]
    pub keystore: K,
    current: SessionData,
    previous: Option<SessionData>,
}

impl<K: SessionKeyStore<SessionData>> Session<K> {
    pub fn new(init: &SessionInit, keystore: K) -> Session<K> {
        let mut session_tag = [0u8; KEY_LENGTH];
        let hkdf = HkdfSha256::new(Some(&[0u8; KEY_LENGTH]), &init.root_key);
        hkdf.expand(SESSION_TAG_INFO, &mut session_tag)
            .expect("HKDF failed");

        let mut session = Session {
            keystore,
            current: SessionData {
                session_tag: SessionTag(session_tag),
                remote_identity: init.remote_identity,
                root_key: RootKey {
                    secret_key: init
                        .secret_key
                        .clone()
                        .unwrap_or_else(|| StaticSecret::random_from_rng(rand_core::OsRng)),
                    key: init.root_key,
                },
                sending_header_keys: init
                    .sending_header_key
                    .map(|hk| HeaderKeys::new(HeaderKey(hk)))
                    .unwrap_or_default(),
                receiving_header_keys: init
                    .receiving_header_key
                    .map(|hk| HeaderKeys::new(HeaderKey(hk)))
                    .unwrap_or_default(),
                sending_chain_key: None,
                receiving_chain_key: None,
            },
            previous: None,
        };

        let public_key = session.public_key();
        session.keystore.set_hash_key(
            &HashKey(Sha256::digest(public_key.as_bytes()).into()),
            &SessionTag(session_tag),
        );

        session_tag.zeroize();

        let mut sending_header_keys = session.current.sending_header_keys.clone();

        if let Some(remote_key) = init.remote_key {
            session.current.sending_chain_key = Some(
                session
                    .expand(&remote_key, &mut sending_header_keys, 0)
                    .unwrap(),
            );
        }

        session.current.sending_header_keys = sending_header_keys;
        session.commit();

        session
    }

    pub fn get_session_tag(&self) -> SessionTag {
        self.current.session_tag.clone()
    }

    pub fn public_key(&self) -> PublicKey {
        self.current.root_key.public_key()
    }

    pub fn hash_key(&self) -> Result<HashKey, DoubleRatchetError> {
        if self.current.sending_chain_key.is_some() {
            Ok(HashKey(Sha256::digest(self.public_key().as_bytes()).into()))
        } else {
            Err(DoubleRatchetError::NoSendingChain)
        }
    }

    fn expand(
        &mut self,
        remote_key: &PublicKey,
        header_keys: &mut HeaderKeys,
        previous_count: u32,
    ) -> Result<ChainKey, DoubleRatchetError> {
        let local_identity = self.keystore.get_verifying_key();
        let remote_identity = &self.current.remote_identity;

        let (key_1, key_2) = if local_identity.as_bytes() < remote_identity.as_bytes() {
            (local_identity.as_bytes(), remote_identity.as_bytes())
        } else {
            (remote_identity.as_bytes(), local_identity.as_bytes())
        };

        let mut info_buf = [0u8; 128];
        let mut offset = 0;

        info_buf[offset..offset + SESSION_INFO.len()].copy_from_slice(SESSION_INFO);
        offset += SESSION_INFO.len();

        info_buf[offset..offset + 32].copy_from_slice(&self.get_session_tag().0);
        offset += 32;

        info_buf[offset..offset + 32].copy_from_slice(key_1);
        offset += 32;

        info_buf[offset..offset + 32].copy_from_slice(key_2);

        let (mut chain_key, next_header_key) = self
            .current
            .root_key
            .expand(remote_key.clone(), Some(&info_buf))
            .map_err(|_| DoubleRatchetError::ChainInitFailed)?;

        info_buf.zeroize();
        chain_key.prev = previous_count;

        header_keys.update(next_header_key);

        Ok(chain_key)
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

    pub fn header_key(&self) -> Option<HeaderKey> {
        self.current.sending_header_keys.header_key()
    }

    pub fn get_sending_key(
        &mut self,
    ) -> Result<(MessageKey, SessionHeader, Option<HeaderKey>), DoubleRatchetError> {
        let public_key = self.public_key();

        let chain = self
            .current
            .sending_chain_key
            .as_mut()
            .ok_or(DoubleRatchetError::NoSendingChain)?;

        let msg_key = chain.expand();
        let header_key: Option<HeaderKey> = self.current.sending_header_keys.header_key();

        Ok((msg_key, chain.header(public_key), header_key))
    }

    pub fn get_receiving_key(
        &mut self,
        header: &SessionHeader,
    ) -> Result<MessageKey, DoubleRatchetError> {
        let session_tag = self.get_session_tag();

        if let Some(key) = self.keystore.get_previous_keys(&session_tag) {
            return Ok(key);
        }

        let is_new_remote_key = match &self.current.receiving_chain_key {
            Some(chain) => chain.compare(&header.public_key),
            None => true,
        };

        if is_new_remote_key {
            let previous_rc_count = self
                .current
                .receiving_chain_key
                .as_ref()
                .map_or(0, |c| c.count);
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
            let current_rc_count = self
                .current
                .receiving_chain_key
                .as_ref()
                .map_or(0, |c| c.count);
            if header.count < current_rc_count {
                return Err(DoubleRatchetError::ChainNotFound);
            }
            if header.count.saturating_sub(current_rc_count) > MAX_SKIP {
                return Err(DoubleRatchetError::MaxSkipExceeded);
            }
        }

        if is_new_remote_key {
            let old_receiving_chain = self.current.receiving_chain_key.clone();
            let mut previous_count = old_receiving_chain.as_ref().map(|c| c.count).unwrap_or(0);
            let mut rc_header_keys = self.current.receiving_header_keys.clone();

            if let Some(mut rc) = old_receiving_chain {
                while rc.count < header.previous {
                    let key = rc.expand();
                    self.keystore.set_previous_keys(&session_tag, &key);
                }
                previous_count = rc.count;
            }

            self.current.receiving_chain_key = Some(self.expand(
                &header.get_public_key(),
                &mut rc_header_keys,
                previous_count,
            )?);

            self.current.root_key.update();

            let new_pub_key = self.current.root_key.public_key();
            let hash_key: [u8; 32] = Sha256::digest(new_pub_key.as_bytes()).into();

            if let Some(header_key) = rc_header_keys.header_key() {
                self.keystore
                    .set_header_key(&HashKey(hash_key), &header_key);
            }

            self.current.receiving_header_keys = rc_header_keys;

            self.keystore.set_hash_key(&HashKey(hash_key), &session_tag);

            let old_sending_chain = self.current.sending_chain_key.clone();
            let sending_chain_count = old_sending_chain.as_ref().map(|c| c.count).unwrap_or(0);

            let mut sc_header_keys = self.current.sending_header_keys.clone();

            self.current.sending_chain_key = Some(self.expand(
                &header.get_public_key(),
                &mut sc_header_keys,
                sending_chain_count,
            )?);
            self.current.sending_header_keys = sc_header_keys;
        }

        let receiving_chain = self.current.receiving_chain_key.as_mut().unwrap();

        let mut final_key: Option<MessageKey> = None;
        while receiving_chain.count < header.count {
            let key = receiving_chain.expand();
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
            .get_data_by_hash(&HashKey(hash_key))
            .ok_or(DoubleRatchetError::SessionNotFound)?;

        Ok((Session::from(&session_data, keystore), header))
    }

    pub fn has_skipped_keys(&self) -> bool {
        self.keystore.has_previous_keys()
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

    impl SessionKeyStore<SessionData> for MemoryKeystore {
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
            let tag = self.session_tag_map.borrow().get(hash_key).cloned()?;
            self.get_data_by_tag(&tag)
        }
        fn get_data_by_tag(&self, session_tag: &SessionTag) -> Option<SessionData> {
            self.session_data.borrow().get(session_tag).cloned()
        }
        fn commit(&self) {}
        fn rollback(&self) -> bool {
            true
        }
    }

    #[test]
    fn test_session_message_exchange() {
        let shared_root_key = [42u8; 32];
        let bob_identity = gen_identity();
        let alice_identity = gen_identity();

        let bob_keystore = MemoryKeystore::new(bob_identity);
        let bob_init = SessionInit {
            remote_identity: alice_identity,
            remote_key: None,
            root_key: shared_root_key,
            secret_key: None,
            sending_header_key: None,
            receiving_header_key: None,
        };
        let mut bob_session = Session::new(&bob_init, bob_keystore);
        let bob_public_key = bob_session.public_key();

        let alice_keystore = MemoryKeystore::new(alice_identity);
        let alice_init = SessionInit {
            remote_identity: bob_identity,
            remote_key: Some(bob_public_key),
            secret_key: None,
            root_key: shared_root_key,
            sending_header_key: None,
            receiving_header_key: None,
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
        let shared_root_key = [7u8; 32];
        let bob_identity = gen_identity();
        let alice_identity = gen_identity();

        let bob_keystore = MemoryKeystore::new(bob_identity);
        let bob_init = SessionInit {
            remote_identity: alice_identity,
            remote_key: None,
            secret_key: None,
            root_key: shared_root_key,
            sending_header_key: None,
            receiving_header_key: None,
        };
        let mut bob_session = Session::new(&bob_init, bob_keystore);
        let bob_public_key = bob_session.public_key();

        let alice_keystore = MemoryKeystore::new(alice_identity);
        let alice_init = SessionInit {
            remote_identity: bob_identity,
            remote_key: Some(bob_public_key),
            secret_key: None,
            root_key: shared_root_key,
            sending_header_key: None,
            receiving_header_key: None,
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
        let shared_root_key = [88u8; 32];
        let alice_identity = gen_identity();
        let bob_identity = gen_identity();
        let keystore = MemoryKeystore::new(alice_identity);

        let bob_secret = StaticSecret::random_from_rng(rand_core::OsRng);
        let bob_pubkey = PublicKey::from(&bob_secret);
        let initial_header_key = [0x11; 32];

        let init = SessionInit {
            remote_identity: bob_identity,
            remote_key: Some(bob_pubkey),
            root_key: shared_root_key,
            secret_key: Some(bob_secret),
            sending_header_key: Some(initial_header_key),
            receiving_header_key: None,
        };

        let mut session = Session::new(&init, keystore);
        let (msg_key, header, header_key) = session.get_sending_key().unwrap();

        assert_eq!(header.count, 1);
        assert_eq!(header_key.map(|d| d.0), Some(initial_header_key));
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
            root_key: [2u8; 32],
            secret_key: None,
            sending_header_key: Some([3u8; 32]),
            receiving_header_key: None,
        };
        let mut session = Session::new(&bob_init, bob_keystore);

        let fake_remote = PublicKey::from(&StaticSecret::random_from_rng(rand_core::OsRng));
        let mut hk = HeaderKeys::default();
        session.current.sending_chain_key = Some(session.expand(&fake_remote, &mut hk, 5).unwrap());

        let bytes = session.current.to_bytes();
        let decoded = SessionData::from_bytes(&bytes);

        assert_eq!(session.current.session_tag.0, decoded.session_tag.0);
        assert_eq!(
            session.current.remote_identity.as_bytes(),
            decoded.remote_identity.as_bytes()
        );
        assert_eq!(
            session.current.root_key.secret_key.to_bytes(),
            decoded.root_key.secret_key.to_bytes()
        );
        assert_eq!(
            session.current.sending_header_keys,
            decoded.sending_header_keys
        );
        assert_eq!(
            session.current.receiving_header_keys,
            decoded.receiving_header_keys
        );
        assert!(decoded.sending_chain_key.is_some());
        assert_eq!(decoded.sending_chain_key.clone().unwrap().prev, 5);
    }

    #[test]
    fn test_max_skip_exceeded_rejection() {
        let shared_root_key = [7u8; 32];
        let bob_identity = gen_identity();
        let alice_identity = gen_identity();
        let bob_keystore = MemoryKeystore::new(bob_identity);
        let bob_init = SessionInit {
            remote_identity: alice_identity,
            remote_key: None,
            secret_key: None,
            root_key: shared_root_key,
            sending_header_key: None,
            receiving_header_key: None,
        };
        let mut bob_session = Session::new(&bob_init, bob_keystore);

        let fake_header = SessionHeader {
            count: super::MAX_SKIP + 1,
            previous: 0,
            public_key: PublicKey::from(&StaticSecret::random_from_rng(rand_core::OsRng)),
        };

        let result = bob_session.get_receiving_key(&fake_header);
        assert_eq!(result.err(), Some(DoubleRatchetError::MaxSkipExceeded));
    }

    #[test]
    fn test_invalid_header_past_previous_count() {
        let shared_root_key = [8u8; 32];
        let bob_identity = gen_identity();
        let alice_identity = gen_identity();
        let bob_keystore = MemoryKeystore::new(bob_identity);
        let bob_init = SessionInit {
            remote_identity: alice_identity,
            remote_key: None,
            secret_key: None,
            root_key: shared_root_key,
            sending_header_key: None,
            receiving_header_key: None,
        };
        let mut bob_session = Session::new(&bob_init, bob_keystore);

        let old_remote = PublicKey::from(&StaticSecret::random_from_rng(rand_core::OsRng));
        let mut hk = HeaderKeys::default();
        let mut mock_rc = bob_session.expand(&old_remote, &mut hk, 0).unwrap();
        mock_rc.count = 50;
        bob_session.current.receiving_chain_key = Some(mock_rc);

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
            root_key: [2u8; 32],
            secret_key: None,
            sending_header_key: None,
            receiving_header_key: None,
        };
        let mut session = Session::new(&init, bob_keystore);

        session.commit();

        let fake_remote = PublicKey::from(&StaticSecret::random_from_rng(rand_core::OsRng));
        let mut hk = HeaderKeys::default();
        let new_chain = session.expand(&fake_remote, &mut hk, 0).unwrap();
        session.current.receiving_chain_key = Some(new_chain);

        let rolled_back = session.rollback();
        assert!(
            rolled_back,
            "Il rollback dovrebbe avere successo se esiste uno stato precedente"
        );
        assert!(
            !session.rollback(),
            "Non è possibile fare un doppio rollback consecutivo"
        );
    }
}
