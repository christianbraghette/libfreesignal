use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

mod double_ratchet;
mod x3dh;

#[derive(Clone, Zeroize, ZeroizeOnDrop, Eq, Hash, PartialEq, Debug)]
pub struct UserId(pub [u8; 32]);

pub type KeyHash = [u8; 32];

#[derive(Clone, Zeroize, ZeroizeOnDrop, Eq, Hash, PartialEq)]
pub struct SessionTag(pub [u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootKey(pub [u8; 32]);

const MESSAGE_KEY_INFO: &[u8] = b"/freesignal/payload/v0.1";

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MessageKey(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEncryptionError();

impl std::fmt::Display for MessageEncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Failed crypto operation")
    }
}

impl std::error::Error for MessageEncryptionError {}

impl MessageKey {
    fn derive_crypto_material(&self) -> ([u8; 32], [u8; 12]) {
        let hkdf = Hkdf::<Sha256>::new(None, &self.0);
        let mut derived = [0u8; 44]; 
        hkdf.expand(MESSAGE_KEY_INFO, &mut derived).expect("HKDF size is valid");

        let mut key = [0u8; 32];
        key.copy_from_slice(&derived[..32]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&derived[32..44]);
        
        // Pulisci il materiale grezzo dalla memoria
        derived.zeroize(); 

        (key, nonce)
    }

    pub fn encrypt_payload(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, MessageEncryptionError> {
        let (key, nonce) = self.derive_crypto_material();
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| MessageEncryptionError())?;
        let nonce = Nonce::from_slice(&nonce);

        let payload = aes_gcm::aead::Payload {
            msg: plaintext,
            aad: associated_data,
        };

        cipher
            .encrypt(&nonce, payload)
            .map_err(|_| MessageEncryptionError())
    }

    pub fn decrypt_payload(
        &self,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, MessageEncryptionError> {
        let (key, nonce) = self.derive_crypto_material();
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|_| MessageEncryptionError())?;
        let nonce = Nonce::from_slice(&nonce);

        let payload = aes_gcm::aead::Payload {
            msg: ciphertext,
            aad: associated_data,
        };

        cipher
            .decrypt(&nonce, payload)
            .map_err(|_| MessageEncryptionError())
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop, Eq, Hash, PartialEq, Debug)]
pub struct HeaderKey(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderEncryptionError();

impl std::fmt::Display for HeaderEncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Failed crypto operation")
    }
}

impl std::error::Error for HeaderEncryptionError {}

impl HeaderKey {
    pub fn encrypt_header<const N: usize,  H: Header<N>>(
        &self,
        header: &H,
    ) -> Result<Vec<u8>, HeaderEncryptionError> {
        let key = Key::<Aes256Gcm>::from_slice(&self.0);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // Genera 12 byte

        let ciphertext = cipher
            .encrypt(&nonce, header.to_bytes().as_slice())
            .map_err(|_| HeaderEncryptionError())?; // Risultato: 36 (dati) + 16 (tag) = 52 byte

        let mut output = Vec::new();
        output.extend_from_slice(&nonce); // 12 byte
        output.extend_from_slice(&ciphertext); // 52 byte

        Ok(output)
    }

    pub fn decrypt_header<const N: usize, H: Header<N>>(
        &self,
        bytes: &[u8],
    ) -> Result<H, HeaderEncryptionError> {
        let nonce = Nonce::from_slice(&bytes[..12]);
        let ciphertext_with_tag = &bytes[12..];

        let key = Key::<Aes256Gcm>::from_slice(&self.0);
        let cipher = Aes256Gcm::new(key);

        let plaintext = cipher
            .decrypt(nonce, ciphertext_with_tag)
            .map_err(|_| HeaderEncryptionError())?;

        let mut raw = [0u8; N];
        raw.copy_from_slice(&plaintext);

        Ok(H::from_bytes(&raw))
    }
}

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

pub trait Header<const N: usize> {
    fn get_public_key(&self) -> PublicKey;
    fn to_bytes(&self) -> [u8; N];
    fn from_bytes(bytes: &[u8; N]) -> Self;

    /*fn decrypt<K: HeaderKeyStore>(
        encrypted_bytes: &[u8; 96],
        keystore: &K,
    ) -> Result<Self, HeaderEncryptionError>
    where
        Self: Sized;*/
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
