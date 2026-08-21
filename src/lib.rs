use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

mod double_ratchet;
mod x3dh;

#[derive(Clone, Zeroize, ZeroizeOnDrop, Eq, Hash, PartialEq, Debug)]
pub struct UserId(pub [u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop, Eq, Hash, PartialEq)]
pub struct HashKey(pub [u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop, Eq, Hash, PartialEq)]
pub struct SessionTag(pub [u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop, Eq, Hash, PartialEq)]
pub struct RootKey(pub [u8; 32]);

const MESSAGE_KEY_INFO: &[u8] = b"/freesignal/payload/v0.1";

#[derive(Clone, Zeroize, ZeroizeOnDrop, Eq, Hash, PartialEq)]
pub struct MessageKey(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEncryptionError();

impl std::fmt::Display for MessageEncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Failed crypto operation")
    }
}

impl std::error::Error for MessageEncryptionError {}

const PAD_BLOCK_SIZE: usize = 128;

impl MessageKey {
    fn derive_crypto_material(&self) -> ([u8; 32], [u8; 12]) {
        let hkdf = Hkdf::<Sha256>::new(None, &self.0);
        let mut derived = [0u8; 44];
        hkdf.expand(MESSAGE_KEY_INFO, &mut derived)
            .expect("HKDF size is valid");

        let mut key = [0u8; 32];
        key.copy_from_slice(&derived[..32]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&derived[32..44]);

        derived.zeroize();

        (key, nonce)
    }

    pub fn encrypt_payload(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, MessageEncryptionError> {
        let (key, nonce) = self.derive_crypto_material();
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| MessageEncryptionError())?;
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
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| MessageEncryptionError())?;
        let nonce = Nonce::from_slice(&nonce);

        let payload = aes_gcm::aead::Payload {
            msg: ciphertext,
            aad: associated_data,
        };

        cipher
            .decrypt(&nonce, payload)
            .map_err(|_| MessageEncryptionError())
    }

    fn pad_plaintext(plaintext: &[u8]) -> Vec<u8> {
        let mut padded = Vec::with_capacity(plaintext.len() + PAD_BLOCK_SIZE);
        padded.extend_from_slice(plaintext);
        padded.push(0x80);

        while padded.len() % PAD_BLOCK_SIZE != 0 {
            padded.push(0x00);
        }

        padded
    }

    fn unpad_plaintext(padded: &[u8]) -> Result<Vec<u8>, MessageEncryptionError> {
        if padded.is_empty() || padded.len() % PAD_BLOCK_SIZE != 0 {
            return Err(MessageEncryptionError());
        }

        let mut pad_len: usize = 0;
        let mut found = 0u8;

        for (i, &b) in padded.iter().rev().enumerate() {
            let is_delimiter = (b == 0x80) as usize;
            let is_valid_so_far = (found == 0) as usize;

            let update_mask = is_delimiter & is_valid_so_far;
            pad_len = (pad_len * (1 - update_mask)) + ((i + 1) * update_mask);

            let is_not_zero = (b != 0x00) as u8;
            found = found | is_not_zero;
        }

        if pad_len == 0 {
            return Err(MessageEncryptionError());
        }

        let original_len = padded.len() - pad_len;
        Ok(padded[..original_len].to_vec())
    }

    pub fn encrypt_padded_payload(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, MessageEncryptionError> {
        let padded_plaintext = Self::pad_plaintext(plaintext);
        self.encrypt_payload(&padded_plaintext, associated_data)
    }

    pub fn decrypt_padded_payload(
        &self,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, MessageEncryptionError> {
        let padded_plaintext = self.decrypt_payload(ciphertext, associated_data)?;
        Self::unpad_plaintext(&padded_plaintext)
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
    pub fn encrypt_header<const N: usize, H: Header<N>>(
        &self,
        header: &H,
    ) -> Result<Vec<u8>, HeaderEncryptionError> {
        let key = Key::<Aes256Gcm>::from_slice(&self.0);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ciphertext = cipher
            .encrypt(&nonce, header.to_bytes().as_slice())
            .map_err(|_| HeaderEncryptionError())?;

        let mut output = Vec::new();
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);

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

pub trait HeaderKeyStore {
    fn set_header_key(&self, hash_key: &HashKey, value: &HeaderKey);
    fn get_header_key(&self, hash_key: &HashKey) -> Option<HeaderKey>;
}

pub trait SessionKeyStore<const N: usize, D: Data<N>> {
    fn set_hash_key(&self, hash_key: &HashKey, public_key: &PublicKey, session_tag: &SessionTag);

    fn set_data(&self, session: &D);
    fn get_data_by_hash(&self, hash_key: &HashKey) -> Option<D>;
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

#[cfg(test)]
mod crypto_tests {
    use super::*;

    #[test]
    fn test_error_display_formatting() {
        assert_eq!(
            format!("{}", MessageEncryptionError()),
            "Failed crypto operation"
        );
        assert_eq!(
            format!("{}", HeaderEncryptionError()),
            "Failed crypto operation"
        );
    }

    #[test]
    fn test_padding_and_unpadding_valid() {
        let plaintext = b"Hello Signal Protocol";
        let padded = MessageKey::pad_plaintext(plaintext);

        assert_eq!(padded.len() % PAD_BLOCK_SIZE, 0);

        let unpadded = MessageKey::unpad_plaintext(&padded).unwrap();
        assert_eq!(unpadded, plaintext.as_slice());
    }

    #[test]
    fn test_padding_exact_block_size() {
        let plaintext = vec![0x42; PAD_BLOCK_SIZE];
        let padded = MessageKey::pad_plaintext(&plaintext);

        assert_eq!(padded.len(), PAD_BLOCK_SIZE * 2);
        let unpadded = MessageKey::unpad_plaintext(&padded).unwrap();
        assert_eq!(unpadded, plaintext);
    }

    #[test]
    fn test_unpad_invalid_length_or_empty() {
        let empty: &[u8] = &[];
        assert!(MessageKey::unpad_plaintext(empty).is_err());

        let invalid_len = vec![0x00; PAD_BLOCK_SIZE + 1];
        assert!(MessageKey::unpad_plaintext(&invalid_len).is_err());
    }

    #[test]
    fn test_unpad_missing_delimiter() {
        let invalid_pad = vec![0x00; PAD_BLOCK_SIZE];
        assert!(MessageKey::unpad_plaintext(&invalid_pad).is_err());
    }

    #[test]
    fn test_payload_encryption_decryption() {
        let key = MessageKey([0xAA; 32]);
        let plaintext = b"Secret data";
        let aad = b"Associated Data Context";

        let ciphertext = key.encrypt_padded_payload(plaintext, aad).unwrap();

        let decrypted = key.decrypt_padded_payload(&ciphertext, aad).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted);

        assert!(
            key.decrypt_padded_payload(&ciphertext, b"Wrong Context")
                .is_err()
        );

        let mut corrupted = ciphertext.clone();
        corrupted[0] ^= 0xFF;
        assert!(key.decrypt_padded_payload(&corrupted, aad).is_err());
    }

    #[derive(Clone)]
    struct DummyHeader([u8; 32]);
    impl Header<32> for DummyHeader {
        fn get_public_key(&self) -> PublicKey {
            PublicKey::from([0; 32])
        }
        fn to_bytes(&self) -> [u8; 32] {
            self.0
        }
        fn from_bytes(bytes: &[u8; 32]) -> Self {
            Self(*bytes)
        }
    }

    #[test]
    fn test_header_encryption_decryption() {
        let key = HeaderKey([0xBB; 32]);
        let header = DummyHeader([0x42; 32]);

        let encrypted = key.encrypt_header(&header).unwrap();
        assert_eq!(encrypted.len(), 60);

        let decrypted: DummyHeader = key.decrypt_header(&encrypted).unwrap();
        assert_eq!(decrypted.0, header.0);

        let mut tampered = encrypted.clone();
        tampered[15] ^= 0xFF;
        assert!(key.decrypt_header::<32, DummyHeader>(&tampered).is_err());
    }

    #[test]
    fn test_public_identity_derivation() {
        let secret = StaticSecret::random_from_rng(rand_core::OsRng);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret.to_bytes());
        let identity = PublicIdentity(signing_key.verifying_key());

        let user_id = identity.get_user_id();
        assert_ne!(
            user_id.0, [0u8; 32],
            "The derived user_id must not be empty"
        );

        let pub_key = identity.to_public_key();
        assert_ne!(
            pub_key.as_bytes(),
            &[0u8; 32],
            "Conversion to PublicKey must not be empty"
        );
    }
}
