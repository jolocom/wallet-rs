extern crate didcomm_rs;

use didcomm_rs::{Message, crypto::SignatureAlgorithm};
use crate::{Error, unlocked::UnlockedWallet};

impl UnlockedWallet {
    /// Takes instance of JSON `Message` as a &str and encrypts it using provided `key_id`.
    /// All JWE related headers along with proper algorithm should be set in `message`.
    pub fn create_message(&self, key_id: &str, message: &str) -> Result<String, Error> {
        if let Some(kp) = &self.contents.get(key_id) {
            let sk = kp.private_key(); 
            Message::receive(message, None)?
                .seal(kp.private_key())
        } else {
            Err(Error::KeyNotFound)
        }
    }
    ///
    pub fn create_signed_message(&self, key_id: String, sign_key_id: String, message: &str, signature_algorithm: &str)
        -> Result<String, Error> {
            let alg: SignatureAlgorithm = signature_algorithm.into();
            if let Some(kp) = &self.contents.get(&sign_key_id) &&
            if let Some(ekp) = &self.contents.get(&key_id) {
                let pk = &kp.public_key.public_key;
                let sk = &kp.private_key();
            Message::receive(message, None)?
                .seal_signed(ekp.private_key(), [pk, sk].join(), alg)
            } else {
                Err(Error::KeyNotFound)
            }
    }
    /// 
    pub fn receive_message(&self, msg_bytes: &[u8]) -> Result<Message, Error> {
        todo!()
    }
}

