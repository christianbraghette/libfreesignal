use std::error::Error;

use ed25519_dalek::SigningKey;
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
    fn get_tag(&self) -> SessionTag;
    fn set_data(&self, session: &Data);
    fn get_data(&self, public_key_hash: &KeyHash) -> Option<Data>;
    fn set_header_key(&self, header_key: &KeyHash, value: &HeaderKey);
    fn get_header_key(&self, header_key: &KeyHash) -> Option<HeaderKey>;
    fn set_previous_keys(&self, hash: &HeaderHash, value: &MessageKey);
    fn get_previous_keys(&self, hash: &HeaderHash) -> Option<MessageKey>;
    fn del_previous_keys(&self) -> bool;
    fn has_skipped_keys(&self) -> bool;
    fn commit(&self);
    fn rollback(&self) -> bool;
}

pub trait Session<Data, K: SessionKeyStore<Data>, H: Header, E: Error> {
    fn new(init: &SessionInit, keystore: K) -> Self;
    fn commit(&mut self);
    fn rollback(&mut self) -> bool;
    fn get_sending_key(&mut self) -> Result<(MessageKey, H, Option<HeaderKey>), E>;
    fn get_receiving_key(&mut self, header: &H) -> Result<MessageKey, E>;
    fn has_skipped_keys(&self) -> bool;
    fn from_header(hash: &KeyHash, header: &[u8], keystore: K) -> (Option<HeaderKey>, Self);
}
