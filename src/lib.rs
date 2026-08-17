use std::error::Error;

use ed25519_dalek::SigningKey;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

mod double_ratchet;
mod scka;
mod x3dh;

#[derive(Clone, Zeroize, ZeroizeOnDrop, Eq, Hash, PartialEq, Debug)]
pub struct UserId(pub [u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MessageKey(pub [u8; 32]);

pub trait KeyExchangeStore {
    fn get_secret_key(&self) -> StaticSecret;
    fn get_signing_key(&self) -> SigningKey;
    fn store_pre_key(&self, prekey_hash: &[u8], prekey: &StaticSecret);
    fn load_pre_key(&self, prekey_hash: &[u8]) -> Option<StaticSecret>;
    fn remove_pre_key(&self, prekey_hash: &[u8]) -> bool;
}

pub type HeaderHash = [u8; 32];
pub type KeyHash = [u8; 32];
pub type ChainID = i64;

#[derive(Clone, Zeroize, ZeroizeOnDrop, Eq, Hash, PartialEq)]
pub struct SessionTag(pub [u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootKey(pub [u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop, Eq, Hash, PartialEq, Debug)]
pub struct HeaderKey(pub [u8; 32]);

pub trait Header {
    fn hash(&self) -> HeaderHash;
    fn to_bytes(&self) -> [u8; 36];
    fn from_bytes(bytes: &[u8; 36]) -> Self;
}

#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct SessionInit {
    pub user_id: UserId,
    pub remote_key: Option<PublicKey>,
    pub root_key: RootKey,
    pub header_key: Option<HeaderKey>,
    pub next_header_key: Option<HeaderKey>,
}

pub trait SessionKeyStore<Data, Chain> {
    fn set_key_chain(&self, key: Option<ChainID>, value: &Chain) -> ChainID;
    fn get_key_chain(&self, id: ChainID) -> Option<Chain>;
    fn del_key_chain(&self, id: ChainID) -> bool;
    fn get_session_data(&self, hash: &[u8; 32]) -> Option<Data>; //hash of public_key
    fn set_header_key(&self, key: &KeyHash, value: &HeaderKey);
    fn get_header_key(&self, key: &KeyHash) -> Option<HeaderKey>;
    fn set_previous_keys(&self, key: &HeaderHash, value: &MessageKey);
    fn get_previous_keys(&self, key: &HeaderHash) -> Option<MessageKey>;
    fn del_previous_keys(&self) -> bool;
    fn commit(&self, session: &Data);
    fn rollback(&self) -> bool;
}

pub trait Session<Data, Chain, K: SessionKeyStore<Data, Chain> + Clone, H: Header, E: Error> {
    fn new(init: &SessionInit, keystore: K) -> Self;
    fn commit(&mut self);
    fn rollback(&mut self) -> bool;

    fn init_chain(
        &mut self,
        remote_key: &PublicKey,
        header_key: Option<&HeaderKey>,
        previous_count: Option<u16>,
    ) -> (Option<ChainID>, Chain);

    fn get_sending_key(&mut self) -> Result<(MessageKey, H, Option<HeaderKey>), E>;

    fn get_receiving_key(&mut self, header: &H) -> Result<MessageKey, E>;

    fn from_header(hash: &KeyHash, header: &[u8], keystore: K) -> (Option<HeaderKey>, Self);
}
