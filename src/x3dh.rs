use crate::{HeaderKey, KeyExchangeStore, PublicIdentity, RootKey, SessionInit};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

const KEY_LENGTH: usize = 32;
const HASH_LENGTH: usize = 32;
const X3DH_INFO: &[u8] = b"/freesignal/x3dh/v0.1";
const PREFIX_F: [u8; 32] = [0xFF; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyExchangeError {
    VerificationError,
    PreKeyNotFound,
}

impl std::fmt::Display for KeyExchangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VerificationError => write!(f, "Error validating PreKey signature"),
            Self::PreKeyNotFound => write!(f, "The requested PreKey was not found in the keystore"),
        }
    }
}
impl std::error::Error for KeyExchangeError {}

pub fn get_identity_x25519_secret(signing_key: &SigningKey) -> StaticSecret {
    let hash = Sha512::digest(signing_key.as_bytes());
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&hash[..32]);
    StaticSecret::from(scalar_bytes)
}

#[derive(Clone)]
pub struct PreKeyBundle<const N: usize> {
    pub identity_key: VerifyingKey,
    pub signed_pre_key: PublicKey,
    pub signature: Signature,
    pub onetime_pre_keys: Option<[PublicKey; N]>,
}

#[derive(Clone)]
pub struct PreKeyMessage {
    pub identity_key: VerifyingKey,
    pub ephemeral_key: PublicKey,
    pub signed_pre_key_hash: [u8; HASH_LENGTH],
    pub onetime_pre_key_hash: Option<[u8; HASH_LENGTH]>,
}

pub struct KeyExchange<K: KeyExchangeStore> {
    pub keystore: K,
    pub identity: PublicIdentity,
}

impl<K: KeyExchangeStore> KeyExchange<K> {
    pub fn new(identity: PublicIdentity, keystore: K) -> KeyExchange<K> {
        KeyExchange { keystore, identity }
    }

    fn derive_session_keys(raw_material: &[u8]) -> (RootKey, HeaderKey, HeaderKey) {
        let mut derived = [0u8; KEY_LENGTH * 3];
        let hkdf = Hkdf::<Sha256>::new(Some(&[0u8; KEY_LENGTH]), raw_material);
        hkdf.expand(X3DH_INFO, &mut derived)
            .expect("HKDF output size is fixed and valid");

        let mut root_key = [0u8; KEY_LENGTH];
        root_key.copy_from_slice(&derived[..KEY_LENGTH]);

        let mut header_key1 = [0u8; KEY_LENGTH];
        header_key1.copy_from_slice(&derived[KEY_LENGTH..KEY_LENGTH * 2]);

        let mut header_key2 = [0u8; KEY_LENGTH];
        header_key2.copy_from_slice(&derived[KEY_LENGTH * 2..]);

        derived.zeroize();

        (
            RootKey(root_key),
            HeaderKey(header_key1),
            HeaderKey(header_key2),
        )
    }

    pub fn generate_spk(&self) -> (StaticSecret, [u8; 32]) {
        let signed_pre_key = StaticSecret::random_from_rng(rand_core::OsRng);
        let signed_pre_key_hash: [u8; 32] =
            Sha256::digest(PublicKey::from(&signed_pre_key).as_bytes()).into();
        self.keystore
            .store_pre_key(&signed_pre_key_hash, &signed_pre_key);
        (signed_pre_key, signed_pre_key_hash)
    }

    pub fn generate_opk(&self, spk_hash: &[u8]) -> (StaticSecret, [u8; 32]) {
        let onetime_pre_key = StaticSecret::random_from_rng(rand_core::OsRng);
        let onetime_pre_key_hash: [u8; 32] =
            Sha256::digest(PublicKey::from(&onetime_pre_key).as_bytes()).into();
        let mut hash = [0u8; 64];
        hash[..32].copy_from_slice(spk_hash);
        hash[32..].copy_from_slice(&onetime_pre_key_hash);
        self.keystore.store_pre_key(&hash, &onetime_pre_key);
        (onetime_pre_key, onetime_pre_key_hash)
    }

    pub fn create_pre_key_bundle<const N: usize>(&self) -> PreKeyBundle<N> {
        let (signed_pre_key_secret, signed_pre_key_hash) = self.generate_spk();
        let onetime_pre_keys: Option<[PublicKey; N]> = Some(std::array::from_fn(|_| {
            let (opk, _) = self.generate_opk(&signed_pre_key_hash);
            PublicKey::from(&opk)
        }));
        let public_key = PublicKey::from(&signed_pre_key_secret);
        PreKeyBundle {
            identity_key: self.identity.get_key(),
            signed_pre_key: public_key,
            signature: self.keystore.get_signing_key().sign(public_key.as_bytes()),
            onetime_pre_keys,
        }
    }

    pub fn process_pre_key_bundle<const N: usize>(
        &self,
        bundle: &PreKeyBundle<N>,
    ) -> Result<(SessionInit, PreKeyMessage), KeyExchangeError> {
        let ephemeral_key = StaticSecret::random_from_rng(rand_core::OsRng);

        bundle
            .identity_key
            .verify_strict(bundle.signed_pre_key.as_ref(), &bundle.signature)
            .map_err(|_| KeyExchangeError::VerificationError)?;

        let remote_user_id = PublicIdentity(bundle.identity_key).get_user_id();

        let onetime_pre_key = bundle.onetime_pre_keys.as_ref().and_then(|keys| {
            if keys.is_empty() {
                None
            } else {
                let random_index = (OsRng.next_u32() as usize) % keys.len();
                Some(keys[random_index])
            }
        });
        let signed_pre_key_hash: [u8; 32] = Sha256::digest(bundle.signed_pre_key.as_bytes()).into();
        let onetime_pre_key_hash: Option<[u8; 32]> =
            onetime_pre_key.map(|data| Sha256::digest(data.as_bytes()).into());

        let mut raw: [u8; KEY_LENGTH * 5] = [0u8; KEY_LENGTH * 5];
        let mut raw_len = KEY_LENGTH * 4;

        raw[..KEY_LENGTH].copy_from_slice(&PREFIX_F);

        let identity_x25519_secret = get_identity_x25519_secret(&self.keystore.get_signing_key());

        raw[KEY_LENGTH..KEY_LENGTH * 2].copy_from_slice(
            identity_x25519_secret
                .diffie_hellman(&bundle.signed_pre_key)
                .as_bytes(),
        );

        raw[KEY_LENGTH * 2..KEY_LENGTH * 3].copy_from_slice(
            ephemeral_key
                .diffie_hellman(&PublicKey::from(
                    bundle.identity_key.to_montgomery().to_bytes(),
                ))
                .as_bytes(),
        );

        raw[KEY_LENGTH * 3..KEY_LENGTH * 4].copy_from_slice(
            ephemeral_key
                .diffie_hellman(&bundle.signed_pre_key)
                .as_bytes(),
        );

        if let Some(pre_key) = onetime_pre_key {
            raw[KEY_LENGTH * 4..]
                .copy_from_slice(ephemeral_key.diffie_hellman(&pre_key).as_bytes());
            raw_len = KEY_LENGTH * 5;
        }

        let (root_key, header_key, next_header_key) = Self::derive_session_keys(&raw[..raw_len]);

        raw.zeroize();

        Ok((
            SessionInit {
                user_id: remote_user_id, // Associa il UserId remoto a SessionInit
                remote_key: Some(bundle.signed_pre_key),
                secret_key: None,
                root_key,
                header_key: Some(header_key),
                next_header_key: Some(next_header_key),
            },
            PreKeyMessage {
                identity_key: self.identity.get_key(),
                ephemeral_key: PublicKey::from(&ephemeral_key),
                signed_pre_key_hash,
                onetime_pre_key_hash,
            },
        ))
    }

    pub fn process_pre_key_message(
        &self,
        message: PreKeyMessage,
    ) -> Result<SessionInit, KeyExchangeError> {
        let remote_user_id = PublicIdentity(message.identity_key).get_user_id();

        let signed_pre_key = self
            .keystore
            .load_pre_key(&message.signed_pre_key_hash)
            .ok_or(KeyExchangeError::PreKeyNotFound)?;

        let onetime_pre_key = if let Some(opk_hash) = message.onetime_pre_key_hash {
            let mut hash = [0u8; HASH_LENGTH * 2];
            hash[..KEY_LENGTH].copy_from_slice(&message.signed_pre_key_hash);
            hash[KEY_LENGTH..].copy_from_slice(&opk_hash);

            let key = self
                .keystore
                .load_pre_key(&hash)
                .ok_or(KeyExchangeError::PreKeyNotFound)?;
            self.keystore.remove_pre_key(&hash);
            Some(key)
        } else {
            None
        };

        let mut raw: [u8; KEY_LENGTH * 5] = [0u8; KEY_LENGTH * 5];
        let mut raw_len = KEY_LENGTH * 4;

        raw[..KEY_LENGTH].copy_from_slice(&PREFIX_F);

        let identity_x25519_secret = get_identity_x25519_secret(&self.keystore.get_signing_key());

        raw[KEY_LENGTH..KEY_LENGTH * 2].copy_from_slice(
            signed_pre_key
                .diffie_hellman(&PublicKey::from(
                    message.identity_key.to_montgomery().to_bytes(),
                ))
                .as_bytes(),
        );

        raw[KEY_LENGTH * 2..KEY_LENGTH * 3].copy_from_slice(
            identity_x25519_secret
                .diffie_hellman(&message.ephemeral_key)
                .as_bytes(),
        );

        raw[KEY_LENGTH * 3..KEY_LENGTH * 4].copy_from_slice(
            signed_pre_key
                .diffie_hellman(&message.ephemeral_key)
                .as_bytes(),
        );

        if let Some(pre_key) = onetime_pre_key {
            raw[KEY_LENGTH * 4..]
                .copy_from_slice(pre_key.diffie_hellman(&message.ephemeral_key).as_bytes());
            raw_len = KEY_LENGTH * 5;
        }

        let (root_key, next_header_key, header_key) = Self::derive_session_keys(&raw[..raw_len]);

        raw.zeroize();

        Ok(SessionInit {
            user_id: remote_user_id, // Associa il UserId di Alice a SessionInit
            remote_key: None,
            secret_key: Some(signed_pre_key),
            root_key,
            header_key: Some(header_key),
            next_header_key: Some(next_header_key),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::double_ratchet::{SESSION_DATA_SIZE, SessionData};
    use crate::{Data, HashKey, HeaderKeyStore, MessageKey, SessionKeyStore, SessionTag};
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct MockKeyStore {
        signing_key: SigningKey,
        store: Arc<Mutex<HashMap<Vec<u8>, StaticSecret>>>,
    }

    impl MockKeyStore {
        fn new() -> Self {
            let secret_key = StaticSecret::random_from_rng(OsRng);
            Self {
                signing_key: SigningKey::from_bytes(&secret_key.to_bytes()),
                store: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    impl KeyExchangeStore for MockKeyStore {
        fn get_signing_key(&self) -> SigningKey {
            self.signing_key.clone()
        }

        fn store_pre_key(&self, prekey_hash: &[u8], prekey: &StaticSecret) {
            self.store
                .lock()
                .unwrap()
                .insert(prekey_hash.to_vec(), prekey.clone());
        }

        fn load_pre_key(&self, prekey_hash: &[u8]) -> Option<StaticSecret> {
            self.store.lock().unwrap().get(prekey_hash).cloned()
        }

        fn remove_pre_key(&self, prekey_hash: &[u8]) -> bool {
            self.store.lock().unwrap().remove(prekey_hash).is_some()
        }
    }

    #[derive(Clone, Default)]
    struct MemorySessionKeystore {
        header_keys: Rc<RefCell<HashMap<HashKey, HeaderKey>>>,
        previous_keys: Rc<RefCell<HashMap<SessionTag, MessageKey>>>,
        session_data: Rc<RefCell<HashMap<SessionTag, SessionData>>>,
        pub_key_map: Rc<RefCell<HashMap<HashKey, PublicKey>>>, // Aggiunto per set_public_key
        session_tag_map: Rc<RefCell<HashMap<HashKey, SessionTag>>>,
    }

    impl HeaderKeyStore for MemorySessionKeystore {
        fn set_header_key(&self, key: &HashKey, value: &HeaderKey) {
            self.header_keys.borrow_mut().insert(key.clone(), value.clone());
        }

        fn get_header_key(&self, key: &HashKey) -> Option<HeaderKey> {
            self.header_keys.borrow().get(key).cloned()
        }
    }

    impl SessionKeyStore<{SESSION_DATA_SIZE}, SessionData> for MemorySessionKeystore {

        fn set_previous_keys(&self, key: &SessionTag, value: &crate::MessageKey) {
            self.previous_keys
                .borrow_mut()
                .insert(key.clone(), value.clone());
        }

        fn get_previous_keys(&self, key: &SessionTag) -> Option<crate::MessageKey> {
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
            self.session_data.borrow_mut().insert(session.get_session_tag(), session.clone());
        }

        fn set_hash_key(&self, hash_key: &HashKey, public_key: &PublicKey, session_tag: &SessionTag) {
            self.pub_key_map
                .borrow_mut()
                .insert(hash_key.clone(), public_key.clone());
            self.session_tag_map
                .borrow_mut()
                .insert(hash_key.clone(), session_tag.clone());
        }

        fn get_data_by_hash(&self, hash_key: &HashKey) -> Option<SessionData> {
            let tag = self
                .session_tag_map
                .borrow()
                .get(&hash_key)
                .cloned()?;
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

    fn create_test_identity(keystore: &MockKeyStore) -> PublicIdentity {
        PublicIdentity(keystore.get_signing_key().verifying_key())
    }

    #[test]
    fn test_pre_key_bundle_signature_verification() {
        let keystore = MockKeyStore::new();
        let identity = create_test_identity(&keystore);
        let session = KeyExchange::new(identity, keystore.clone());

        let bundle: PreKeyBundle<5> = session.create_pre_key_bundle();

        let verification = bundle
            .identity_key
            .verify_strict(bundle.signed_pre_key.as_bytes(), &bundle.signature);

        assert!(
            verification.is_ok(),
            "La firma crittografica della Signed Pre-Key deve essere valida"
        );
    }

    #[test]
    fn test_create_pre_key_bundle_opk_generation() {
        let keystore = MockKeyStore::new();
        let identity = create_test_identity(&keystore);
        let session = KeyExchange::new(identity, keystore.clone());

        const MAX_OPK: usize = 10;
        let bundle: PreKeyBundle<MAX_OPK> = session.create_pre_key_bundle();

        assert!(bundle.onetime_pre_keys.is_some());
        let opks = bundle.onetime_pre_keys.unwrap();
        assert_eq!(opks.len(), MAX_OPK);

        let store_guard = keystore.store.lock().unwrap();
        assert_eq!(store_guard.len(), MAX_OPK + 1);
    }

    #[test]
    fn test_x3dh_full_handshake_end_to_end() {
        let bob_keystore = MockKeyStore::new();
        let bob_identity = create_test_identity(&bob_keystore);
        let bob_kx = KeyExchange::new(bob_identity, bob_keystore);
        let bob_bundle: PreKeyBundle<5> = bob_kx.create_pre_key_bundle();

        let alice_keystore = MockKeyStore::new();
        let alice_identity = create_test_identity(&alice_keystore);
        let alice_kx = KeyExchange::new(alice_identity, alice_keystore);

        let (alice_init, pre_key_msg) = alice_kx
            .process_pre_key_bundle(&bob_bundle)
            .expect("Alice deve elaborare il bundle con successo");

        let bob_init = bob_kx
            .process_pre_key_message(pre_key_msg)
            .expect("Bob deve elaborare il messaggio con successo");

        // 4. VERIFICA FONDAMENTALE: Le RootKey calcolate devono essere IDENTICHE
        assert_eq!(
            alice_init.root_key.0, bob_init.root_key.0,
            "Handshake X3DH fallito: Alice e Bob hanno calcolato RootKey differenti!"
        );

        // Le chiavi di header trasversali devono combaciare
        assert_eq!(alice_init.header_key, bob_init.next_header_key);
        assert_eq!(alice_init.next_header_key, bob_init.header_key);

        // 5. Verifica che le sessioni derivate comunichino via Double Ratchet
        type DR = crate::double_ratchet::Session<MemorySessionKeystore>;

        let mut alice_dr = DR::new(&alice_init, MemorySessionKeystore::default());
        let mut bob_dr = DR::new(&bob_init, MemorySessionKeystore::default());

        let (alice_msg_key, header, _) = alice_dr.get_sending_key().unwrap();
        let bob_msg_key = bob_dr.get_receiving_key(&header).unwrap();

        assert_eq!(
            alice_msg_key.0, bob_msg_key.0,
            "La chiave derivata da Bob deve coincidere con quella di Alice"
        );
    }

    #[test]
    fn test_x3dh_handshake_without_opk() {
        let bob_keystore = MockKeyStore::new();
        let bob_identity = create_test_identity(&bob_keystore);
        let bob_kx = KeyExchange::new(bob_identity, bob_keystore);

        let mut bundle: PreKeyBundle<0> = bob_kx.create_pre_key_bundle();
        bundle.onetime_pre_keys = None;

        let alice_keystore = MockKeyStore::new();
        let alice_identity = create_test_identity(&alice_keystore);
        let alice_kx = KeyExchange::new(alice_identity, alice_keystore);

        let (alice_init, pre_key_msg) = alice_kx.process_pre_key_bundle(&bundle).unwrap();
        let bob_init = bob_kx.process_pre_key_message(pre_key_msg).unwrap();

        assert_eq!(
            alice_init.root_key.0, bob_init.root_key.0,
            "Handshake senza OPK deve produrre la stessa RootKey"
        );
    }
}