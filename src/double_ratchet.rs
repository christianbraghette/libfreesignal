use crate::{Data, HashKey, Header, HeaderKeyStore};
use crate::{HeaderKey, MessageKey, RootKey, SessionInit, SessionKeyStore, SessionTag, UserId};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

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
const CHAIN_INFO: &[u8] = b"/freesignal/double_ratchet/keychain/v0.1";
const SESSION_TAG_INFO: &[u8] = b"/freesignal/double_ratchet/tag/v0.1";

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ChainKey(pub [u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionHeader {
    pub count: u32,
    pub previous: u32,
    pub remote_key: PublicKey,
}

impl Header<40> for SessionHeader {
    fn get_public_key(&self) -> PublicKey {
        self.remote_key
    }

    fn to_bytes(&self) -> [u8; 40] {
        let mut raw = [0u8; 40];
        raw[0..4].copy_from_slice(&self.count.to_be_bytes());
        raw[4..8].copy_from_slice(&self.previous.to_be_bytes());
        raw[8..40].copy_from_slice(self.remote_key.as_bytes());
        raw
    }

    fn from_bytes(bytes: &[u8; 40]) -> Self {
        let mut count = [0u8; 4];
        count.copy_from_slice(&bytes[0..4]);

        let mut previous = [0u8; 4];
        previous.copy_from_slice(&bytes[4..8]);

        let mut remote_key = [0u8; 32];
        remote_key.copy_from_slice(&bytes[8..40]);

        Self {
            count: u32::from_be_bytes(count),
            previous: u32::from_be_bytes(previous),
            remote_key: PublicKey::from(remote_key),
        }
    }
}

pub const SESSION_DATA_SIZE: usize = 192 + CHAIN_SIZE * 2;

#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct SessionData {
    session_tag: SessionTag,
    user_id: UserId,
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
        raw[32..64].copy_from_slice(&self.user_id.0);
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
        let mut user_id = [0u8; 32];
        user_id.copy_from_slice(&bytes[32..64]);
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
            user_id: UserId(user_id),
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
pub struct Session<K: SessionKeyStore<SESSION_DATA_SIZE, SessionData> + HeaderKeyStore> {
    #[zeroize(skip)]
    pub keystore: K,
    current: SessionData,
    previous: Option<SessionData>,
}

impl<K: SessionKeyStore<SESSION_DATA_SIZE, SessionData> + HeaderKeyStore> Session<K> {
    pub fn new(init: &SessionInit, keystore: K) -> Session<K> {
        let mut session_tag = [0u8; KEY_LENGTH];
        let hkdf = Hkdf::<Sha256>::new(Some(&[0u8; KEY_LENGTH]), init.root_key.0.as_ref());
        hkdf.expand(SESSION_TAG_INFO, &mut session_tag)
            .expect("HKDF failed");

        let mut session = Session {
            keystore,
            current: SessionData {
                session_tag: SessionTag(session_tag),
                user_id: init.user_id.clone(),
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
            &public_key,
            &SessionTag(session_tag),
        );

        session_tag.zeroize();

        if let Some(ref nhk) = init.next_header_key {
            let hash = HashKey(Sha256::digest(session.get_public_key().as_bytes()).into());
            session.keystore.set_header_key(&hash, nhk);
        }

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

    pub fn get_user_id(&self) -> UserId {
        self.current.user_id.clone()
    }

    pub fn get_session_tag(&self) -> SessionTag {
        self.current.session_tag.clone()
    }

    pub fn get_public_key(&self) -> PublicKey {
        PublicKey::from(&self.current.secret_key)
    }

    fn init_chain(
        &mut self,
        remote_key: &PublicKey,
        header_key: Option<&HeaderKey>,
        previous_count: Option<u32>,
    ) -> Result<Chain, DoubleRatchetError> {
        let shared_key = self.current.secret_key.diffie_hellman(remote_key);
        let mut hash_key = [0u8; KEY_LENGTH * 3];
        let hkdf = Hkdf::<Sha256>::new(Some(&self.current.root_key.0), shared_key.as_bytes());
        hkdf.expand(SESSION_INFO, &mut hash_key)
            .map_err(|_| DoubleRatchetError::ChainInitFailed)?;

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
                rc_header_key = rc_header_key.or(rc.header_key.clone())
            }

            let new_rc = self.init_chain(
                &header.get_public_key(),
                rc_header_key.as_ref(),
                previous_count,
            )?;
            self.current.receiving_chain = Some(new_rc.clone());

            let hash: [u8; 32] = Sha256::digest(self.get_public_key().as_bytes()).into();
            self.keystore
                .set_header_key(&HashKey(hash), &new_rc.next_header_key);

            if self.current.next_header_key.is_some() {
                self.current.next_header_key = None;
            }

            self.current.secret_key = StaticSecret::random_from_rng(rand_core::OsRng);

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

    pub fn from_header(bytes: &[u8], keystore: K) -> Result<Self, DoubleRatchetError> {
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
        } else {
            return Err(DoubleRatchetError::InvalidHeader);
        };

        let session_data = keystore
            .get_data_by_hash(&HashKey(Sha256::digest(&header.remote_key).into()))
            .ok_or(DoubleRatchetError::SessionNotFound)?;

        Ok(Session::from(&session_data, keystore))
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
        let mut hash_key = [0u8; 64];
        let hkdf = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &self.chain_key.0);
        hkdf.expand(CHAIN_INFO, &mut hash_key).unwrap();

        self.chain_key.0.copy_from_slice(&hash_key[..32]);
        let mut msg_key = [0u8; 32];
        msg_key.copy_from_slice(&hash_key[32..64]);

        hash_key.zeroize();

        self.count += 1;
        MessageKey(msg_key)
    }

    fn get_header(&self) -> SessionHeader {
        SessionHeader {
            count: self.count,
            previous: self.previous_count,
            remote_key: self.public_key,
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
        if bytes.len() == CHAIN_SIZE {
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
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    #[derive(Clone, Default)]
    struct MemoryKeystore {
        header_keys: Rc<RefCell<HashMap<HashKey, HeaderKey>>>,
        previous_keys: Rc<RefCell<HashMap<SessionTag, MessageKey>>>,
        session_data: Rc<RefCell<HashMap<SessionTag, SessionData>>>,
        pub_key_map: Rc<RefCell<HashMap<HashKey, PublicKey>>>, // Aggiunto per set_public_key
        session_tag_map: Rc<RefCell<HashMap<HashKey, SessionTag>>>,
    }

    impl MemoryKeystore {
        fn new() -> Self {
            Self::default()
        }

        pub fn set_session_data(&self, value: &SessionData) {
            self.session_data
                .borrow_mut()
                .insert(value.get_session_tag(), value.clone());
        }
    }

    impl HeaderKeyStore for MemoryKeystore {
        fn set_header_key(&self, key: &HashKey, value: &HeaderKey) {
            self.header_keys
                .borrow_mut()
                .insert(key.clone(), value.clone());
        }

        fn get_header_key(&self, key: &HashKey) -> Option<HeaderKey> {
            self.header_keys.borrow().get(key).cloned()
        }
    }

    impl SessionKeyStore<{ SESSION_DATA_SIZE }, SessionData> for MemoryKeystore {
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

        fn set_hash_key(
            &self,
            hash_key: &HashKey,
            public_key: &PublicKey,
            session_tag: &SessionTag,
        ) {
            self.pub_key_map
                .borrow_mut()
                .insert(hash_key.clone(), public_key.clone());
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

    // --- 2. UNIT TEST ---

    #[test]
    fn test_session_message_exchange() {
        let shared_root_key = RootKey([42u8; 32]); // Chiave radice derivata da X3DH

        // ====================================================================
        // FASE 1: INIZIALIZZAZIONE
        // ====================================================================

        // Inizializziamo Bob (il ricevente originale)
        let bob_keystore = MemoryKeystore::new();
        let bob_init = SessionInit {
            user_id: UserId(Sha256::digest("bob").into()),
            remote_key: None, // Bob aspetta che Alice inizi
            root_key: shared_root_key.clone(),
            secret_key: None,
            header_key: None,
            next_header_key: None,
        };
        let mut bob_session = Session::new(&bob_init, bob_keystore);
        let bob_public_key = PublicKey::from(&bob_session.current.secret_key);

        // Inizializziamo Alice (il mittente originale)
        let alice_keystore = MemoryKeystore::new();
        let alice_init = SessionInit {
            user_id: UserId(Sha256::digest("alice").into()),
            remote_key: Some(bob_public_key), // Alice conosce la chiave di Bob
            secret_key: None,
            root_key: shared_root_key,
            header_key: None,
            next_header_key: None,
        };
        let mut alice_session = Session::new(&alice_init, alice_keystore);

        // ====================================================================
        // FASE 2: ALICE INVIA IL PRIMO MESSAGGIO A BOB
        // ====================================================================

        let (alice_msg_key_1, header_1, _) = alice_session.get_sending_key().unwrap();

        // Bob riceve e computa la chiave
        let bob_msg_key_1 = bob_session.get_receiving_key(&header_1).unwrap();

        // Le chiavi del messaggio derivate indipendentemente devono coincidere!
        assert_eq!(
            alice_msg_key_1.0, bob_msg_key_1.0,
            "Le chiavi del primo messaggio non corrispondono"
        );

        // Verifica del cricchetto simmetrico.
        // get_key() incrementa il contatore PRIMA di restituire la chiave,
        // quindi il primo messaggio mai inviato su una catena ha count == 1,
        // non 0 (0 e' lo stato iniziale della catena, prima di ogni get_key()).
        assert_eq!(header_1.count, 1);

        // ====================================================================
        // FASE 3: ALICE INVIA UN SECONDO MESSAGGIO (Symmetric Ratchet)
        // ====================================================================

        let (alice_msg_key_2, header_2, _) = alice_session.get_sending_key().unwrap();
        let bob_msg_key_2 = bob_session.get_receiving_key(&header_2).unwrap();

        assert_eq!(
            alice_msg_key_2.0, bob_msg_key_2.0,
            "Le chiavi del secondo messaggio non corrispondono"
        );

        // Il counter della catena di invio di Alice deve essersi incrementato:
        // dopo il secondo get_key() il conteggio passa da 1 a 2.
        assert_eq!(header_2.count, 2);

        // ====================================================================
        // FASE 4: BOB RISPONDE AD ALICE (DH Ratchet / Asymmetric Ratchet)
        // ====================================================================

        // Bob ora invia un messaggio ad Alice. Questo forzerà lo scatto
        // del cricchetto asimmetrico e la creazione di nuove catene
        let (bob_reply_key_1, header_reply_1, _) = bob_session.get_sending_key().unwrap();
        let alice_reply_key_1 = alice_session.get_receiving_key(&header_reply_1).unwrap();

        assert_eq!(
            bob_reply_key_1.0, alice_reply_key_1.0,
            "Le chiavi della risposta di Bob non corrispondono"
        );

        // Controlliamo l'integrità del counter:
        // È una nuova catena di invio appena creata (Bob -> Alice); dopo il
        // primo get_key() il count vale 1 (stesso discorso di header_1.count).
        assert_eq!(header_reply_1.count, 1);
        // "previous" riporta quanti messaggi Bob aveva mandato nella SUA
        // vecchia catena di invio (non quanti ne ha ricevuti da Alice: quello
        // è tracciato dalla receiving chain, non dalla sending chain). Bob
        // non aveva ancora mai inviato nulla, quindi vale 0.
        assert_eq!(header_reply_1.previous, 0);
    }

    #[test]
    fn test_skipped_key_is_single_use() {
        let shared_root_key = RootKey([7u8; 32]);

        let bob_keystore = MemoryKeystore::default();
        let bob_init = SessionInit {
            user_id: UserId(Sha256::digest("bob").into()),
            remote_key: None,
            secret_key: None,
            root_key: shared_root_key.clone(),
            header_key: None,
            next_header_key: None,
        };
        let mut bob_session = Session::new(&bob_init, bob_keystore);
        let bob_public_key = PublicKey::from(&bob_session.current.secret_key);

        let alice_keystore = MemoryKeystore::default();
        let alice_init = SessionInit {
            user_id: UserId(Sha256::digest("alice").into()),
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
            "La chiave del messaggio saltato deve essere usata una sola volta"
        );
        let _ = bob_key_1_first;
    }

    #[test]
    fn test_session_get_sending_key_header_key_retrieval() {
        let shared_root_key = RootKey([88u8; 32]);
        let keystore = MemoryKeystore::new();

        let bob_secret = StaticSecret::random_from_rng(rand_core::OsRng);
        let bob_pubkey = PublicKey::from(&bob_secret);
        let initial_header_key = HeaderKey([0x11; 32]);

        let init = SessionInit {
            user_id: UserId([1u8; 32]),
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
}
