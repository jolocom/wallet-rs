extern crate didcomm_rs;

use std::convert::TryInto;
use crypto_box::PublicKey;
use didcomm_rs::{DidcommHeader, Jwk, KeyAlgorithm, Message, crypto::{SignatureAlgorithm, Signer}};
use x25519_dalek::{StaticSecret};
use crate::{prelude::*, Error, unlocked::UnlockedWallet, contents::Content};

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
    /// * `sign_key_id` - identifier of the `Content` to be used for signing;
    /// * `message` - fully populated JSON serialized `Message` ready for sealing;
    /// * `header` - JSON serialized `DidcommHeader`. Ready for send.
    ///
    pub fn seal_signed(&self, key_id: &str, sign_key_id: &str, message: &str, header: &str)
        -> Result<String, Error> {
            if let Some(kp) = self.contents.get(sign_key_id) {
                match kp {
                    Content::KeyPair(kp) => {
                        let mut jws = Message::new()
                            .set_didcomm_header(serde_json::from_str(header)?);
                        let mut key = Jwk::new();
                        let alg: SignatureAlgorithm;
                        match kp.public_key.key_type {
                            KeyType::JwsVerificationKey2020 => {
                                key.kty = Some(String::from("EC"));
                                key.crv = Some(String::from("P-256"));
                                key.kid = Some(calc_kid(&self.id, &kp.public_key.controller[0]));
                                key.add_other_header(String::from("x"), base64::encode(&kp.public_key.public_key));
                                alg = SignatureAlgorithm::Es256;
                            },
                            KeyType::Ed25519VerificationKey2018 => {
                                key.alg = KeyAlgorithm::EdDsa;
                                key.kty = Some(String::from("OKP"));
                                key.crv = Some(String::from("Ed25519"));
                                key.kid = Some(calc_kid(&self.id, &kp.public_key.controller[0]));
                                key.add_other_header(String::from("x"), base64::encode(&kp.public_key.public_key));
                                alg = SignatureAlgorithm::EdDsa;
                            },
                            KeyType::EcdsaSecp256k1VerificationKey2019 |
                            KeyType::EcdsaSecp256k1RecoveryMethod2020 => {
                                key.alg = KeyAlgorithm::EcdhEs;
                                key.kty = Some(String::from("EC"));
                                key.crv = Some(String::from("secp256k1"));
                                key.kid = Some(calc_kid(&self.id, &kp.public_key.controller[0]));
                                key.add_other_header(String::from("x"), base64::encode(&kp.public_key.public_key));
                                alg = SignatureAlgorithm::Es256k;
                            },
                            _ => return Err(Error::UnsupportedKeyType)
                        }
                        jws.jwm_header.kid = key.kid.clone();
                        jws.jwm_header.alg = Some(key.alg.to_string());
                        jws.jwm_header.cty = Some(String::from("JWM"));
                        jws.jwm_header.jwk = Some(key);
                        jws = jws.body(message.as_bytes());
                        self
                            .seal_encrypted(key_id, &jws.sign(alg.signer(), &kp.private_key())?, header)
                    },
                _ => Err(Error::KeyNotFound),
                }
            } else {
                Err(Error::KeyNotFound)
        }
    }
    /// Signt `Message` into JWS and then seal it into `JWE` using didcomm_rs crypto
    /// # Parameters
    /// * `key_id` - identifier of the `Content` to be used for encryption;
    /// * `message` - fully populated JSON serialized `Message` ready for sealing;
    /// * `header` - JSON serialized `DidcommHeader`. Ready for send.
    /// controller = "did:keri:ulc'3hu/l'390/rl'acehu/#kid"
    pub fn seal_encrypted(&self, key_id: &str, message: &str, header: &str)
        -> Result<String, Error> {
        if let Some(ekp) = self.contents.get(key_id) {
            match ekp {
                Content::KeyPair(ekp) => {
                    let mut e_key = Jwk::new();
                    match ekp.public_key.key_type {
                        KeyType::X25519KeyAgreementKey2019 => {
                            e_key.crv = Some(String::from("x25519"));
                            e_key.kid = Some(calc_kid(&self.id, &ekp.public_key.controller[0]));
                            e_key.add_other_header(String::from("x"), base64::encode(&ekp.public_key.public_key));
                        },
                        _ => return Err(Error::UnsupportedKeyType)
                    }
                    let mut jwe = Message::new();
                    jwe.jwm_header.kid = e_key.kid.clone();
                    jwe.jwm_header.alg = Some(e_key.alg.to_string());
                    jwe.jwm_header.cty = Some(String::from("JWM"));
                    jwe.jwm_header.jwk = Some(e_key);
                    jwe.set_didcomm_header(serde_json::from_str(header)?)
                        .body(message.as_bytes())
                        .seal(&ekp.private_key())
                        .map_err(|e| Error::DidcommError(e))
                },
                _ => return Err(Error::UnsupportedKeyType)
            }
        } else {
            Err(Error::KeyNotFound)
        }
    }
    /// Processes JWS or JWE from bytes sent by the sender
    /// Returns instance of raw `Message`
    ///
    pub fn receive_message(&self, msg_bytes: &[u8], sender_public_key: &[u8], verifying_key: Option<&[u8]>) -> Result<Message, Error> {
        let h: DidcommHeader = serde_json::from_slice(msg_bytes)?;
        if let Some(kp) = self.get_content_from_header(&h.to) {
            match kp {
                Content::KeyPair(unwrapped_kp) => {
                    let pk = unwrapped_kp.private_key();
                    let arr: [u8; 32] = pk.as_slice().try_into()
                        .map_err(|_| Error::WrongKeyLength)?;
                    let pk_arr: [u8; 32] = sender_public_key.try_into()
                            .map_err(|_| Error::WrongKeyLength)?;
                    let public = PublicKey::from(pk_arr);
                    let shared = StaticSecret::from(arr)
                        .diffie_hellman(&public);
                    Ok(Message::receive(
                    &String::from_utf8_lossy(msg_bytes),
                    Some(shared.as_bytes()), 
                    verifying_key
                    )?)
                },
                _ => return Err(Error::ContentNotFound(h.to.iter().map(|s| s.to_owned()).collect::<String>()))
            }
        } else {
            Err(Error::DidcommError(didcomm_rs::Error::JweParseError))
        }
    }

    // helper method to parse keypair `Content` id from incomming `kid`
    fn get_content_from_header(&self, ids: &Vec<String>) -> Option<&Content> {
        for id in ids {
            let all: Vec<&str> = id.split("#").collect();
            if all.len() != 2 {
                continue;
            }
            let r = self.contents.get(all[1]);
            if let Some(c) = r {
                return Some(c);
            } else { continue; }
        }
        None
    }
}

// helper function to calculate `kid` JWK header based on:
// walled id + # + key controller
fn calc_kid(id: &str, cntrlr: &str) -> String {
    [id, cntrlr].join("#")
}


