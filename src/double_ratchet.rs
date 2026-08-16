use crate::{MessageKey, UserId};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoubleRatchetError {
    NoSendingChain,
    NoReceivingChain,
    ChainNotFound,
}
impl std::fmt::Display for DoubleRatchetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSendingChain => write!(f, "Uninitialized sending chain"),
            Self::NoReceivingChain => write!(f, "Uninitialized receiving chain"),
            Self::ChainNotFound => write!(f, "Chain not found"),
        }
    }
}
impl std::error::Error for DoubleRatchetError {}

const KEY_LENGTH: usize = 32;
const SESSION_INFO: &[u8] = b"/freesignal/double_ratchet/v0.1";
const CHAIN_INFO: &[u8] = b"/freesignal/double_ratchet/keychain/v0.1";
const SESSION_TAG_INFO: &[u8] = b"/freesignal/double_ratchet/tag/v0.1";

type HeaderHash = [u8; 32];
type KeyHash = [u8; 32];
type ChainID = i64;

#[derive(Clone, Zeroize, ZeroizeOnDrop, Eq, Hash, PartialEq)]
pub struct SessionTag(pub [u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootKey(pub [u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HeaderKey(pub [u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ChainKey(pub [u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Header {
    pub count: u16,
    pub previous: u16,
    pub remote_key: PublicKey,
}

impl Header {
    fn hash(&self) -> HeaderHash {
        let mut raw = [0u8; 36];
        raw[..32].copy_from_slice(self.remote_key.as_bytes());
        raw[32..34].copy_from_slice(&self.count.to_be_bytes());
        raw[34..].copy_from_slice(&self.previous.to_be_bytes());
        Sha256::digest(&raw).into()
    }
}

#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct SessionData {
    pub secret_key: StaticSecret,
    pub root_key: RootKey,
    pub header_key: Option<HeaderKey>,
    pub next_header_key: Option<HeaderKey>,
    pub sending_chain: Option<ChainID>,
    pub receiving_chain: Option<ChainID>,
    pub prev_keys_count: u16,
}

pub trait SessionKeyStore {
    fn set_key_chain(&self, key: Option<ChainID>, value: &Chain) -> ChainID;
    fn get_key_chain(&self, id: ChainID) -> Option<Chain>;
    fn del_key_chain(&self, id: ChainID) -> bool;
    fn set_header_key(&self, key: &KeyHash, value: &HeaderKey);
    fn get_header_key(&self, key: &KeyHash) -> Option<HeaderKey>;
    fn set_previous_keys(&self, key: &HeaderHash, value: &MessageKey);
    fn get_previous_keys(&self, key: &HeaderHash) -> Option<MessageKey>;
    fn del_previous_keys(&self) -> bool;
    fn commit(&self, session: &SessionData);
    fn rollback(&self) -> bool;
}

#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct Session<K: SessionKeyStore + Clone> {
    #[zeroize(skip)]
    pub keystore: K,
    pub user_id: UserId,
    pub session_tag: SessionTag,
    current: SessionData,
    previous: Option<SessionData>,
}

#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct SessionInit {
    pub user_id: UserId,
    pub remote_key: Option<PublicKey>,
    pub root_key: RootKey,
    pub header_key: Option<HeaderKey>,
    pub next_header_key: Option<HeaderKey>,
}

impl<K: SessionKeyStore + Clone> Session<K> {
    pub fn new(init: &SessionInit, keystore: K) -> Session<K> {
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
                secret_key: StaticSecret::random_from_rng(rand_core::OsRng),
                sending_chain: None,
                receiving_chain: None,
                prev_keys_count: 0,
            },
            previous: None,
        };

        session_tag.zeroize();

        if let Some(ref nhk) = init.next_header_key {
            let hash: [u8; 32] = Sha256::digest(&nhk.0).into();
            session.keystore.set_header_key(&hash, nhk);
        }

        if let Some(remote_key) = init.remote_key {
            session.current.sending_chain = session
                .init_chain(&remote_key, init.header_key.as_ref(), None)
                .0;
            session.current.header_key = None;
        }

        session
    }

    pub fn commit(&mut self) {
        self.previous = Some(self.current.clone());
        self.keystore.commit(&self.current);
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

    fn init_chain(
        &mut self,
        remote_key: &PublicKey,
        header_key: Option<&HeaderKey>,
        previous_count: Option<u16>,
    ) -> (Option<ChainID>, Chain) {
        let shared_key = self.current.secret_key.diffie_hellman(remote_key);
        let mut hash_key = [0u8; KEY_LENGTH * 3];
        let hkdf = Hkdf::<Sha256>::new(Some(&self.current.root_key.0), shared_key.as_bytes());
        hkdf.expand(SESSION_INFO, &mut hash_key)
            .expect("HKDF failed");

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

        (Some(self.keystore.set_key_chain(None, &chain)), chain)
    }

    pub fn get_sending_key(&mut self) -> Result<(MessageKey, Header), DoubleRatchetError> {
        let chain_id = self
            .current
            .sending_chain
            .ok_or(DoubleRatchetError::NoSendingChain)?;

        let mut chain = self
            .keystore
            .get_key_chain(chain_id)
            .ok_or(DoubleRatchetError::ChainNotFound)?;

        let msg_key = chain.get_key();
        self.keystore.set_key_chain(Some(chain_id), &chain);

        Ok((msg_key, chain.get_header()))
    }

    pub fn get_receiving_key(&mut self, header: &Header) -> Result<MessageKey, DoubleRatchetError> {
        let kh = header.hash();

        // Skipped Keys Search
        if let Some(key) = self.keystore.get_previous_keys(&kh) {
            self.current.prev_keys_count = self.current.prev_keys_count.saturating_sub(1);
            return Ok(key);
        }

        let is_new_remote_key = match self.current.receiving_chain {
            Some(rc_id) => {
                let rc = self
                    .keystore
                    .get_key_chain(rc_id)
                    .ok_or(DoubleRatchetError::ChainNotFound)?;
                // Se restituisce 0, le chiavi NON combaciano (sono diverse)
                rc.remote_key.as_bytes().ct_eq(header.remote_key.as_bytes()).unwrap_u8() == 0
            }
            None => true, 
        };

        // Diffie-Hellman Ratchet Step
        if is_new_remote_key {
            let old_receiving_chain = self.current.receiving_chain
                .and_then(|id| self.keystore.get_key_chain(id));
                
            let mut previous_count = old_receiving_chain.as_ref().map(|c| c.count);

            if let Some(mut rc) = old_receiving_chain.clone() {
                while rc.count < header.previous {
                    let key = rc.get_key();
                    let skipped_hash = rc.get_remote_header().hash();
                    self.keystore.set_previous_keys(&skipped_hash, &key);
                    self.current.prev_keys_count += 1;
                }
                previous_count = Some(rc.count);
                self.keystore.del_key_chain(self.current.receiving_chain.unwrap());
            }

            let next_hk = old_receiving_chain.map(|c| c.next_header_key.clone());
            let rc_header_key = self.current.next_header_key.clone().or(next_hk);

            let (new_rc_id, new_rc) = self.init_chain(
                &header.remote_key, 
                rc_header_key.as_ref(), 
                previous_count
            );
            self.current.receiving_chain = new_rc_id;

            let hash: [u8; 32] = Sha256::digest(&new_rc.next_header_key.0).into();
            self.keystore.set_header_key(&hash, &new_rc.next_header_key);

            if self.current.next_header_key.is_some() {
                self.current.next_header_key = None;
            }

            self.current.secret_key = StaticSecret::random_from_rng(rand_core::OsRng);

            let old_sending_chain_id = self.current.sending_chain;
            let old_sending_chain = old_sending_chain_id
                .and_then(|id| self.keystore.get_key_chain(id));
                
            let sending_chain_count = old_sending_chain.as_ref().map(|c| c.count).unwrap_or(0);
            
            let sc_next_hk = old_sending_chain.map(|c| c.next_header_key.clone());
            let sc_header_key = self.current.header_key.clone().or(sc_next_hk);

            (self.current.sending_chain, _) = self.init_chain(
                &header.remote_key,
                sc_header_key.as_ref(),
                Some(sending_chain_count),
            );

            if self.current.header_key.is_some() {
                self.current.header_key = None;
            }

            // Pulisci vecchia Sending Chain dal DB
            if let Some(old_send_id) = old_sending_chain_id {
                self.keystore.del_key_chain(old_send_id);
            }
        }

        // Symmetric Ratchet
        let receiving_chain_id = self
            .current
            .receiving_chain
            .ok_or(DoubleRatchetError::NoReceivingChain)?;
            
        let mut receiving_chain = self
            .keystore
            .get_key_chain(receiving_chain_id)
            .ok_or(DoubleRatchetError::ChainNotFound)?;

        let mut final_key: Option<MessageKey> = None;
        while receiving_chain.count < header.count {
            let key = receiving_chain.get_key();
            if receiving_chain.count == header.count {
                final_key = Some(key);
            } else {
                let skipped_hash = receiving_chain.get_remote_header().hash();
                self.keystore.set_previous_keys(&skipped_hash, &key);
                self.current.prev_keys_count += 1;
            }
        }

        let final_key = final_key.ok_or(DoubleRatchetError::ChainNotFound)?;

        self.keystore.set_key_chain(Some(receiving_chain_id), &receiving_chain);

        Ok(final_key)
    }

    pub fn get_header_key(&self, hash: Option<KeyHash>) -> Result<Option<HeaderKey>, DoubleRatchetError> {
        if let Some(hk) = hash {
            return Ok(self.keystore.get_header_key(&hk));
        }

        if let Some(hk) = &self.current.header_key {
            return Ok(Some(hk.clone()));
        }

        if let Some(hk) = self.current.sending_chain {
            let sending_chain = self
                .keystore
                .get_key_chain(hk)
                .ok_or(DoubleRatchetError::ChainNotFound)?;

            return Ok(sending_chain.header_key.clone());
        };

        Ok(None)
    }

    pub fn has_skipped_keys(&self) -> bool {
        self.current.prev_keys_count > 0
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
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    // --- 1. MOCK DEL KEYSTORE IN MEMORIA PER I TEST ---

    #[derive(Clone, Default)]
    struct MemoryKeystore {
        chains: Rc<RefCell<HashMap<ChainID, Chain>>>,
        header_keys: Rc<RefCell<HashMap<KeyHash, HeaderKey>>>,
        previous_keys: Rc<RefCell<HashMap<HeaderHash, MessageKey>>>,
        next_chain_id: Rc<RefCell<ChainID>>,
    }

    impl MemoryKeystore {
        fn new() -> Self {
            Self::default()
        }
    }

    impl SessionKeyStore for MemoryKeystore {
        fn set_key_chain(&self, key: Option<ChainID>, value: &Chain) -> ChainID {
            let mut chains = self.chains.borrow_mut();
            let id = key.unwrap_or_else(|| {
                let mut next_id = self.next_chain_id.borrow_mut();
                *next_id += 1;
                *next_id
            });
            chains.insert(id, value.clone());
            id
        }

        fn get_key_chain(&self, id: ChainID) -> Option<Chain> {
            self.chains.borrow().get(&id).cloned()
        }

        fn del_key_chain(&self, id: ChainID) -> bool {
            self.chains.borrow_mut().remove(&id).is_some()
        }

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
            // Leggi-e-cancella: coerente col contratto single-use del trait.
            self.previous_keys.borrow_mut().remove(key)
        }

        fn del_previous_keys(&self) -> bool {
            self.previous_keys.borrow_mut().clear();
            true
        }

        fn commit(&self, _session: &SessionData) {
            // Nei test in memoria, modifichiamo già lo stato real-time.
            // In un DB reale qui faresti la query SQL di COMMIT.
        }

        fn rollback(&self) -> bool {
            // Per semplicità nel test assumiamo che non ci siano errori critici
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
            root_key: shared_root_key,
            header_key: None,
            next_header_key: None,
        };
        let mut alice_session = Session::new(&alice_init, alice_keystore);

        // ====================================================================
        // FASE 2: ALICE INVIA IL PRIMO MESSAGGIO A BOB
        // ====================================================================

        let (alice_msg_key_1, header_1) = alice_session.get_sending_key().unwrap();

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

        let (alice_msg_key_2, header_2) = alice_session.get_sending_key().unwrap();
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
        let (bob_reply_key_1, header_reply_1) = bob_session.get_sending_key().unwrap();
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

        let bob_keystore = MemoryKeystore::new();
        let bob_init = SessionInit {
            user_id: UserId(Sha256::digest("bob").into()),
            remote_key: None,
            root_key: shared_root_key.clone(),
            header_key: None,
            next_header_key: None,
        };
        let mut bob_session = Session::new(&bob_init, bob_keystore);
        let bob_public_key = PublicKey::from(&bob_session.current.secret_key);

        let alice_keystore = MemoryKeystore::new();
        let alice_init = SessionInit {
            user_id: UserId(Sha256::digest("alice").into()),
            remote_key: Some(bob_public_key),
            root_key: shared_root_key,
            header_key: None,
            next_header_key: None,
        };
        let mut alice_session = Session::new(&alice_init, alice_keystore);

        // Alice invia due messaggi, ma Bob riceve prima il secondo (il primo
        // viene "saltato" e la sua chiave finisce tra le previous_keys).
        let (_alice_key_1, header_1) = alice_session.get_sending_key().unwrap();
        let (alice_key_2, header_2) = alice_session.get_sending_key().unwrap();

        let bob_key_2 = bob_session.get_receiving_key(&header_2).unwrap();
        assert_eq!(alice_key_2.0, bob_key_2.0);
        assert!(bob_session.has_skipped_keys());

        // Ora arriva il messaggio 1 (saltato): deve decifrare correttamente...
        let bob_key_1_first = bob_session.get_receiving_key(&header_1).unwrap();
        assert!(!bob_session.has_skipped_keys());

        // ...ma se arrivasse una seconda volta (replay), non deve più trovare
        // la chiave nello store: deve fallire, non restituire di nuovo la stessa.
        let bob_key_1_second = bob_session.get_receiving_key(&header_1);
        assert!(
            bob_key_1_second.is_err(),
            "la chiave del messaggio saltato è stata riletta due volte: non è single-use"
        );
        let _ = bob_key_1_first;
    }
}