use crate::{
    HeaderHash, HeaderKey, KeyHash, MessageKey, RootKey, SessionInit, SessionKeyStore,
    SessionTag, UserId,
};
use crate::{Header as HeaderTrait, Session as SessionTrait};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoubleRatchetError {
    NoSendingChain,
    ChainNotFound,
    MaxSkipExceeded,
    InvalidMessageCount,
    ChainInitFailed,
}
impl std::fmt::Display for DoubleRatchetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSendingChain => write!(f, "Uninitialized sending chain"),
            Self::ChainNotFound => write!(f, "Chain not found"),
            Self::MaxSkipExceeded => write!(f, "Message count exceeds MAX_SKIP threshold"),
            Self::InvalidMessageCount => write!(f, "Invalid message count in header"),
            Self::ChainInitFailed => write!(f, "Failed chain init"),
        }
    }
}
impl std::error::Error for DoubleRatchetError {}

const KEY_LENGTH: usize = 32;
const MAX_SKIP: u16 = 2000;
const SESSION_INFO: &[u8] = b"/freesignal/double_ratchet/v0.1";
const CHAIN_INFO: &[u8] = b"/freesignal/double_ratchet/keychain/v0.1";
const SESSION_TAG_INFO: &[u8] = b"/freesignal/double_ratchet/tag/v0.1";

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ChainKey(pub [u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Header {
    pub count: u16,
    pub previous: u16,
    pub remote_key: PublicKey,
}

impl HeaderTrait for Header {
    fn get_public_key(&self) -> PublicKey {
        self.remote_key
    }

    fn hash(&self) -> HeaderHash {
        let raw = self.to_bytes();
        Sha256::digest(&raw).into()
    }

    fn to_bytes(&self) -> [u8; 36] {
        let mut raw = [0u8; 36];
        raw[..2].copy_from_slice(&self.count.to_be_bytes());
        raw[2..4].copy_from_slice(&self.previous.to_be_bytes());
        raw[4..].copy_from_slice(self.remote_key.as_bytes());
        raw
    }

    fn from_bytes(bytes: &[u8; 36]) -> Self {
        let mut count = [0u8; 2];
        count.copy_from_slice(&bytes[..2]);

        let mut previous = [0u8; 2];
        previous.copy_from_slice(&bytes[2..4]);

        let mut remote_key = [0u8; 32];
        remote_key.copy_from_slice(&bytes[4..]);
        Self {
            count: u16::from_be_bytes(count),
            previous: u16::from_be_bytes(previous),
            remote_key: PublicKey::from(remote_key),
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct SessionData {
    pub secret_key: StaticSecret,
    pub root_key: RootKey,
    pub header_key: Option<HeaderKey>,
    pub next_header_key: Option<HeaderKey>,
    pub sending_chain: Option<Chain>,
    pub receiving_chain: Option<Chain>,
}

#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct Session<K: SessionKeyStore<SessionData>> {
    #[zeroize(skip)]
    pub keystore: K,
    pub user_id: UserId,
    pub session_tag: SessionTag,
    current: SessionData,
    previous: Option<SessionData>,
}

impl<K: SessionKeyStore<SessionData>> Session<K> {
    fn init_chain(
        &mut self,
        remote_key: &PublicKey,
        header_key: Option<&HeaderKey>,
        previous_count: Option<u16>,
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
}

impl<K: SessionKeyStore<SessionData>>
    SessionTrait<SessionData, K, Header, DoubleRatchetError> for Session<K>
{
    fn new(init: &SessionInit, keystore: K) -> Session<K> {
        let mut session_tag = [0u8; KEY_LENGTH];
        let hkdf = Hkdf::<Sha256>::new(Some(&[0u8; KEY_LENGTH]), init.root_key.0.as_ref());
        hkdf.expand(SESSION_TAG_INFO, &mut session_tag)
            .expect("HKDF failed");

        let mut session = Session {
            keystore,
            user_id: init.user_id.clone(),
            session_tag: SessionTag(session_tag),
            current: SessionData {
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

        session_tag.zeroize();

        if let Some(ref nhk) = init.next_header_key {
            let hash: [u8; 32] = Sha256::digest(&nhk.0).into();
            session.keystore.set_header_key(&hash, nhk);
        }

        if let Some(remote_key) = init.remote_key {
            session.current.sending_chain =
                Some(session.init_chain(&remote_key, init.header_key.as_ref(), None).unwrap());
            session.current.header_key = None;
        }

        session
    }

    fn commit(&mut self) {
        self.previous = Some(self.current.clone());
        self.keystore.set_data(&self.current);
        self.keystore.commit();
    }

    fn rollback(&mut self) -> bool {
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

    fn get_sending_key(
        &mut self,
    ) -> Result<(MessageKey, Header, Option<HeaderKey>), DoubleRatchetError> {
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

    fn get_receiving_key(&mut self, header: &Header) -> Result<MessageKey, DoubleRatchetError> {
        let kh = header.hash();

        if let Some(key) = self.keystore.get_previous_keys(&kh) {
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
                return Err(DoubleRatchetError::InvalidMessageCount);
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
                    let skipped_hash = rc.get_remote_header().hash();
                    self.keystore.set_previous_keys(&skipped_hash, &key);
                }
                previous_count = Some(rc.count);
                rc_header_key = rc_header_key.or(rc.header_key.clone())
            }

            let new_rc =
                self.init_chain(&header.get_public_key(), rc_header_key.as_ref(), previous_count)?;
            self.current.receiving_chain = Some(new_rc.clone());

            let hash: [u8; 32] = Sha256::digest(&new_rc.next_header_key.0).into();
            self.keystore.set_header_key(&hash, &new_rc.next_header_key);

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
                let skipped_hash = receiving_chain.get_remote_header().hash();
                self.keystore.set_previous_keys(&skipped_hash, &key);
            }
        }

        final_key.ok_or(DoubleRatchetError::ChainNotFound)
    }

    fn from_header(hash: &KeyHash, header_bytes: &[u8], keystore: K) -> (Option<HeaderKey>, Self) {
        let is_unencrypted = hash.iter().all(|&b| b == 0);

        let (header_key, lookup_hash) = if is_unencrypted {
            let mut remote_key_bytes = [0u8; 32];
            if header_bytes.len() >= 36 {
                remote_key_bytes.copy_from_slice(&header_bytes[4..36]);
            } else if header_bytes.len() >= 32 {
                remote_key_bytes.copy_from_slice(&header_bytes[..32]);
            }

            let computed_hash: [u8; 32] = Sha256::digest(&remote_key_bytes).into();
            (None, computed_hash)
        } else {
            let hk = keystore.get_header_key(hash);
            (hk, *hash)
        };

        let session_data = keystore
            .get_data(&lookup_hash)
            .unwrap_or_else(|| SessionData {
                secret_key: StaticSecret::random_from_rng(rand_core::OsRng),
                root_key: RootKey([0u8; 32]),
                header_key: header_key.clone(),
                next_header_key: None,
                sending_chain: None,
                receiving_chain: None,
            });

        let mut session_tag = [0u8; KEY_LENGTH];
        let hkdf = Hkdf::<Sha256>::new(Some(&[0u8; KEY_LENGTH]), session_data.root_key.0.as_ref());
        hkdf.expand(SESSION_TAG_INFO, &mut session_tag)
            .expect("HKDF failed");

        let session = Session {
            keystore,
            user_id: UserId([0u8; 32]),
            session_tag: SessionTag(session_tag),
            current: session_data,
            previous: None,
        };

        (header_key, session)
    }

    fn has_skipped_keys(&self) -> bool {
        self.keystore.has_skipped_keys()
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Chain {
    pub count: u16,
    pub previous_count: u16,
    pub public_key: PublicKey,
    pub remote_key: PublicKey,
    pub next_header_key: HeaderKey,
    pub header_key: Option<HeaderKey>,
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

    fn get_header(&self) -> Header {
        Header {
            count: self.count,
            previous: self.previous_count,
            remote_key: self.public_key,
        }
    }

    fn get_remote_header(&self) -> Header {
        Header {
            count: self.count,
            previous: self.previous_count,
            remote_key: self.remote_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HeaderHash;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    #[derive(Clone, Default)]
    struct MemoryKeystore {
        header_keys: Rc<RefCell<HashMap<KeyHash, HeaderKey>>>,
        previous_keys: Rc<RefCell<HashMap<HeaderHash, MessageKey>>>,
        session_data: Rc<RefCell<HashMap<[u8; 32], SessionData>>>
    }

    impl MemoryKeystore {
        fn new() -> Self {
            Self::default()
        }

        pub fn set_session_data(&self, hash: &[u8; 32], value: &SessionData) {
            self.session_data.borrow_mut().insert(*hash, value.clone());
        }
    }

    impl SessionKeyStore<SessionData> for MemoryKeystore {
        fn set_header_key(&self, key: &KeyHash, value: &HeaderKey) {
            self.header_keys.borrow_mut().insert(*key, value.clone());
        }

        fn get_header_key(&self, key: &KeyHash) -> Option<HeaderKey> {
            self.header_keys.borrow().get(key).cloned()
        }

        fn set_previous_keys(&self, key: &HeaderHash, value: &MessageKey) {
            self.previous_keys.borrow_mut().insert(*key, value.clone());
        }

        fn get_previous_keys(&self, key: &HeaderHash) -> Option<MessageKey> {
            self.previous_keys.borrow_mut().remove(key)
        }

        fn del_previous_keys(&self) -> bool {
            self.previous_keys.borrow_mut().clear();
            true
        }

        fn has_skipped_keys(&self) -> bool {
            !self.previous_keys.borrow().is_empty()
        }

        fn set_data(&self, _session: &SessionData) {}
        fn commit(&self) {}
        fn rollback(&self) -> bool {
            true
        }

        fn get_data(&self, hash: &[u8; 32]) -> Option<SessionData> {
            self.session_data.borrow().get(hash).cloned()
        }
        
        fn get_tag(&self) -> SessionTag {
            todo!()
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
    fn test_from_header_unencrypted_zero_keyhash() {
        let keystore = MemoryKeystore::new();
        let zero_hash: KeyHash = [0u8; 32];

        let dummy_secret = StaticSecret::random_from_rng(rand_core::OsRng);
        let dummy_pubkey = PublicKey::from(&dummy_secret);
        let header = Header {
            count: 5,
            previous: 1,
            remote_key: dummy_pubkey,
        };
        let header_bytes = header.to_bytes();

        let (header_key, session) = Session::from_header(&zero_hash, &header_bytes, keystore);

        // Se il KeyHash è formato da soli zeri, la HeaderKey deve essere None
        assert!(header_key.is_none());
        assert_eq!(session.user_id, UserId([0u8; 32]));
    }

    #[test]
    fn test_from_header_encrypted_keyhash() {
        let keystore = MemoryKeystore::new();
        let expected_hk = HeaderKey([0xCC; 32]);
        let key_hash: KeyHash = Sha256::digest(&expected_hk.0).into();

        keystore.set_header_key(&key_hash, &expected_hk);

        let dummy_secret = StaticSecret::random_from_rng(rand_core::OsRng);
        let dummy_pubkey = PublicKey::from(&dummy_secret);
        let header = Header {
            count: 1,
            previous: 0,
            remote_key: dummy_pubkey,
        };
        let header_bytes = header.to_bytes();

        let (header_key, _session) = Session::from_header(&key_hash, &header_bytes, keystore);

        // Quando il KeyHash è valido, la HeaderKey associata deve essere recuperata
        assert_eq!(header_key, Some(expected_hk));
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
