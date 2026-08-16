use crate::UserId;
use crate::double_ratchet::{HeaderKey, RootKey, SessionInit};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;
use rand_core::{OsRng, RngCore};

const KEY_LENGTH: usize = 32;
const HASH_LENGTH: usize = 32;
const X3DH_INFO: &[u8] = b"/freesignal/x3dh/v0.1";

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

pub trait KeyExchangeStore {
    fn get_secret_key(&self) -> StaticSecret;
    fn get_signing_key(&self) -> SigningKey;
    fn store_pre_key(&self, prekey_hash: &[u8], prekey: &StaticSecret);
    fn load_pre_key(&self, prekey_hash: &[u8]) -> Option<StaticSecret>;
    fn remove_pre_key(&self, prekey_hash: &[u8]) -> bool;
}

const PUBLIC_ID_INFO: &[u8] = b"freesignal/user_id/v0.1";

#[derive(Clone)]
pub struct PublicIdentity(VerifyingKey);

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

        // PULIZIA MEMORIA: Sovrascrive i byte dell'output HKDF con zeri
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

        let mut raw: [u8; KEY_LENGTH * 4] = [0u8; KEY_LENGTH * 4];
        let mut raw_len = KEY_LENGTH * 3;

        raw[..KEY_LENGTH].copy_from_slice(
            self.keystore
                .get_secret_key()
                .diffie_hellman(&bundle.signed_pre_key)
                .as_ref(),
        );
        raw[KEY_LENGTH..KEY_LENGTH * 2].copy_from_slice(
            ephemeral_key
                .diffie_hellman(&PublicKey::from(
                    bundle.identity_key.to_montgomery().to_bytes(),
                ))
                .as_bytes(),
        );
        raw[KEY_LENGTH * 2..KEY_LENGTH * 3].copy_from_slice(
            ephemeral_key
                .diffie_hellman(&bundle.signed_pre_key)
                .as_bytes(),
        );

        if let Some(pre_key) = onetime_pre_key {
            raw[KEY_LENGTH * 3..]
                .copy_from_slice(ephemeral_key.diffie_hellman(&pre_key).as_bytes());
            raw_len = KEY_LENGTH * 4;
        }

        let (root_key, header_key, next_header_key) = Self::derive_session_keys(&raw[..raw_len]);

        raw.zeroize();

        Ok((
            SessionInit {
                user_id: self.identity.get_user_id(),
                remote_key: Some(self.identity.to_public_key()),
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
        let signed_pre_key = self
            .keystore
            .load_pre_key(&message.signed_pre_key_hash)
            .ok_or(KeyExchangeError::PreKeyNotFound)?;

        let mut hash = [0u8; HASH_LENGTH * 2];
        hash[..KEY_LENGTH].copy_from_slice(&message.signed_pre_key_hash);
        if let Some(onetime_pre_key_hash) = message.onetime_pre_key_hash {
            hash[KEY_LENGTH..].copy_from_slice(&onetime_pre_key_hash);
        }

        let onetime_pre_key = self.keystore.load_pre_key(&hash);
        self.keystore.remove_pre_key(&hash);

        let mut raw: [u8; KEY_LENGTH * 4] = [0u8; KEY_LENGTH * 4];
        let mut raw_len = KEY_LENGTH * 3;

        raw[..KEY_LENGTH].copy_from_slice(
            signed_pre_key
                .diffie_hellman(&PublicKey::from(
                    message.identity_key.to_montgomery().to_bytes(),
                ))
                .as_ref(),
        );
        raw[KEY_LENGTH..KEY_LENGTH * 2].copy_from_slice(
            self.keystore
                .get_secret_key()
                .diffie_hellman(&message.ephemeral_key)
                .as_bytes(),
        );
        raw[KEY_LENGTH * 2..KEY_LENGTH * 3].copy_from_slice(
            signed_pre_key
                .diffie_hellman(&message.ephemeral_key)
                .as_bytes(),
        );

        if let Some(pre_key) = onetime_pre_key {
            raw[KEY_LENGTH * 3..]
                .copy_from_slice(pre_key.diffie_hellman(&message.ephemeral_key).as_bytes());
            raw_len = KEY_LENGTH * 4;
        }

        let (root_key, next_header_key, header_key) = Self::derive_session_keys(&raw[..raw_len]);

        raw.zeroize();

        Ok(SessionInit {
            user_id: self.identity.get_user_id(),
            remote_key: Some(self.identity.to_public_key()),
            root_key,
            header_key: Some(header_key),
            next_header_key: Some(next_header_key),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct MockKeyStore {
        secret_key: StaticSecret,
        signing_key: SigningKey,
        store: Arc<Mutex<HashMap<Vec<u8>, StaticSecret>>>,
    }

    impl MockKeyStore {
        fn new() -> Self {
            let secret_key = StaticSecret::random_from_rng(OsRng);
            Self {
                secret_key: secret_key.clone(),
                signing_key: SigningKey::from_bytes(secret_key.as_bytes()),
                store: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    impl KeyExchangeStore for MockKeyStore {
        fn get_secret_key(&self) -> StaticSecret {
            self.secret_key.clone()
        }

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

    // RISOLUZIONE: L'helper ora accetta il keystore per derivare la chiave pubblica corrispondente
    // alla chiave privata usata per la firma.
    fn create_test_identity(keystore: &MockKeyStore) -> PublicIdentity {
        PublicIdentity(keystore.get_signing_key().verifying_key())
    }

    // --- TEST 1: Verifica della firma del Bundle ---
    #[test]
    fn test_pre_key_bundle_signature_verification() {
        let keystore = MockKeyStore::new();
        // Passiamo il keystore per avere un'identità coerente
        let identity = create_test_identity(&keystore);
        let session = KeyExchange::new(identity.clone(), keystore.clone());

        let bundle: PreKeyBundle<5> = session.create_pre_key_bundle();

        let verification = bundle
            .identity_key
            .verify_strict(bundle.signed_pre_key.as_bytes(), &bundle.signature);

        assert!(
            verification.is_ok(),
            "La firma crittografica della Signed Pre-Key deve essere valida"
        );
    }

    // --- TEST 2: Validazione della logica OPK e Storage ---
    #[test]
    fn test_create_pre_key_bundle_opk_generation() {
        let keystore = MockKeyStore::new();
        let identity = create_test_identity(&keystore);
        let session = KeyExchange::new(identity, keystore.clone());

        const MAX_OPK: usize = 10;
        let bundle: PreKeyBundle<MAX_OPK> = session.create_pre_key_bundle();

        assert!(bundle.onetime_pre_keys.is_some());
        let opks = bundle.onetime_pre_keys.unwrap();
        assert_eq!(
            opks.len(),
            MAX_OPK,
            "Il bundle deve contenere esattamente {} OPK",
            MAX_OPK
        );

        for i in 0..MAX_OPK {
            for j in (i + 1)..MAX_OPK {
                assert_ne!(
                    opks[i].as_bytes(),
                    opks[j].as_bytes(),
                    "Le chiavi OPK devono essere crittograficamente uniche"
                );
            }
        }

        let store_guard = keystore.store.lock().unwrap();
        assert_eq!(
            store_guard.len(),
            MAX_OPK + 1,
            "Il keystore deve contenere la SPK e tutte le OPK"
        );
    }

    // --- TEST 3: Estrazione e formattazione dell'identità (UserId) ---
    #[test]
    fn test_public_identity_hkdf_expansion() {
        // Qui ci basta un mock generico, quindi lo inizializziamo sul momento
        let keystore = MockKeyStore::new();
        let identity = create_test_identity(&keystore);
        let user_id = identity.get_user_id();

        assert_eq!(user_id.0.len(), 32);
        assert_ne!(
            user_id.0, [0u8; 32],
            "L'ID utente derivato non deve essere una slice di soli zeri"
        );
    }
}
