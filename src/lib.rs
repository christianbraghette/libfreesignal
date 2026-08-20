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

pub trait KeyExchangeStore {
    fn get_signing_key(&self) -> SigningKey;
    fn store_pre_key(&self, prekey_hash: &[u8], prekey: &StaticSecret);
    fn load_pre_key(&self, prekey_hash: &[u8]) -> Option<StaticSecret>;
    fn remove_pre_key(&self, prekey_hash: &[u8]) -> bool;
}

pub type HeaderHash = [u8; 32];
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

pub trait Header {
    fn get_public_key(&self) -> PublicKey;
    fn hash(&self) -> HeaderHash;
    fn to_bytes(&self) -> [u8; 36];
    fn from_bytes(bytes: &[u8; 36]) -> Self;
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

pub trait SessionKeyStore<Data> {
    fn set_data(&self, public_key: &SessionTag, session: &Data);
    fn set_public_key(&self, public_key: &PublicKey, session_tag: &SessionTag);
    fn get_data_by_key(&self, public_key: &PublicKey) -> Option<Data>;
    fn get_data_by_tag(&self, session_tag: &SessionTag) -> Option<Data>;

    fn set_header_key(&self, header_key: &KeyHash, value: &HeaderKey);
    fn get_header_key(&self, header_key: &KeyHash) -> Option<HeaderKey>;

    fn set_previous_keys(&self, hash: &HeaderHash, value: &MessageKey);
    fn get_previous_keys(&self, hash: &HeaderHash) -> Option<MessageKey>;
    fn del_previous_keys(&self, hash: Option<&HeaderHash>) -> bool;
    fn has_previous_keys(&self) -> bool;

    fn commit(&self);
    fn rollback(&self) -> bool;
}