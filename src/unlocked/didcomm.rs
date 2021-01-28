extern crate didcomm_rs;

use didcomm_rs::{Message, crypto::SignatureAlgorithm};
use crate::{Error, unlocked::UnlockedWallet, contents::Content};
use std::convert::TryInto;

impl UnlockedWallet {
    /// Helper function to get JSON String of default empty `Message`
    /// 
    pub fn create_message() -> String {
        Message::new()
            .as_raw_json()
            .unwrap() // this should never fail
    }
    /// Takes instance of JSON `Message` as a &str and encrypts it using provided `key_id`.
    /// All JWE related headers along with proper algorithm should be set in `message`.
    /// # Parameters
    /// * `key_id` - identifier of the `Content` to be used for encryption;
    /// * `message` - fully populated JSON serialized `Message` ready for sealing;
    ///
    pub fn seal_encrypted(&self, key_id: &str, message: &str) -> Result<String, Error> {
        if let Some(kp) = self.contents.get(key_id) {
            match kp {
                Content::KeyPair(kp) =>
                    Message::receive(message, None, None)?
                        .seal(&kp.private_key())
                        .map_err(|e| Error::DidcommError(e))
                ,
            _ => Err(Error::KeyNotFound),
            }
        } else {
            Err(Error::KeyNotFound)
        }
    }
    /// Signt `Message` into JWS and then seal it into `JWE` using didcomm_rs crypto
    /// # Parameters
    /// * `key_id` - identifier of the `Content` to be used for encryption;
    /// * `sign_key_id` - identifier of the `Content` to be used for signing;
    /// * `message` - fully populated JSON serialized `Message` ready for sealing;
    /// * `signature_algorithm` - is string representation of one of three DIDComm allowed
    /// algorithms: `EdDSA`, `ES256`, `ES256K`;
    ///
    pub fn seal_signed_message(&self, key_id: String, sign_key_id: String, message: &str, signature_algorithm: &str)
        -> Result<String, Error> {
            let alg: SignatureAlgorithm = (&signature_algorithm.to_string()).try_into()?;
            if let Some(kp) = self.contents.get(&sign_key_id) {
                match kp {
                    Content::KeyPair(kp) => {
                        if let Some(ekp) = self.contents.get(&key_id) {
                            match ekp {
                                Content::KeyPair(ekp) => {
                                    let mut skp = kp.public_key.public_key.to_vec();
                                    skp.append(&mut ekp.private_key().to_vec());
                                    Message::receive(message, None, None)?
                                        .seal_signed(&ekp.private_key(), &skp, alg)
                                        .map_err(|e| Error::DidcommError(e))
                                },
                                _ => Err(Error::KeyNotFound),
                            }
                        } else {
                            Err(Error::KeyNotFound)
                        }
                    },
                    _ => Err(Error::KeyNotFound),
                }
            } else {
                Err(Error::KeyNotFound)
            }
    }
    /// 
    pub fn receive_message(&self, msg_bytes: &[u8]) -> Result<Message, Error> {
        todo!()
    }
}

