use didcomm_rs::{DdoParser, Jwe, Jwk, KeyAlgorithm, Message, crypto::{CryptoAlgorithm, SignatureAlgorithm, Signer}, resolve_any, try_resolve_any};
use crate::{prelude::*, Error, unlocked::UnlockedWallet, contents::Content};

impl UnlockedWallet {
    /// Helper function to get JSON String of default empty `Message`
    /// 
    pub fn create_message() -> String {
        Message::new()
            .as_raw_json()
            .unwrap() // this should never fail
    }
    pub fn create_jwe_message(from: &str, to: &[&str], alg: CryptoAlgorithm) -> String {
        serde_json::to_string(&Message::new()
            .to(to)
            .from(from)
            .as_jwe(&alg)).unwrap()
    }
    /// Takes instance of JSON `Message` as a &str and encrypts it using provided `key_id`.
    /// All JWE related headers along with proper algorithm should be set in `message`.
    /// # Parameters
    /// * `key_id` - identifier of the `Content` to be used for encryption;
    /// * `sign_key_controller` - identifier of the `Content` to be used for signing;
    /// * `message` - fully populated JSON serialized `Message` ready for sealing;
    /// * `header` - JSON serialized `DidcommHeader`. Ready for send.
    ///
    pub fn seal_signed(&self, message: &str)
        -> Result<String, Error> {
            let m: Message = serde_json::from_str(message)?;
            let document = try_resolve_any(&m.get_didcomm_header().from.clone().unwrap_or_default())
                .map_err(|e| Error::Other(e.into()))?;
            let ekp: Option<(String, &Content)> =
                if let Some(ka) = document.find_key_agreement("Ed25519") {
                    if let Some(kp) = self.contents.get_by_controller(&ka.controller) {
                        Some(kp)
                    } else { None }
                } else { None };
            if let Some(kp) = ekp {
                match kp {
                    (_, Content::KeyPair(kp)) => {
                        let mut jws = Message::new()
                            .set_didcomm_header(m.get_didcomm_header().to_owned());
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
                            .seal_encrypted(&jws.sign(alg.signer(), &kp.private_key())?)
                    },
                _ => Err(Error::KeyNotFound),
                }
            } else {
                Err(Error::KeyNotFound)
        }
    }
    /// Signt `Message` into JWS and then seal it into `JWE` using didcomm_rs crypto
    /// # Parameters
    /// * `key_controller` - identifier of the `Content` to be used for encryption;
    /// * `message` - fully populated JSON serialized `Message` ready for sealing;
    /// * `header` - JSON serialized `DidcommHeader`. Ready for send.
    /// controller = "did:keri:ulc'3hu/l'390/rl'acehu/#kid"
    pub fn seal_encrypted(&self, message: &str)
        -> Result<String, Error> {
        let m: Message = serde_json::from_str(message)?;
        let document = try_resolve_any(&m.get_didcomm_header().from.clone().unwrap_or_default())
            .map_err(|e| Error::Other(e.into()))?;
        let ekp: Option<(String, &Content)> =
            if let Some(controller) = document.find_public_key_controller_for_curve("X25519") {
                if let Some(kp) = self.contents.get_by_controller(&controller) {
                    Some(kp)
                } else { None }
            } else { None };
        if let Some(ekp) = ekp {
            match ekp {
                (_, Content::KeyPair(ekp)) => {
                    let mut e_key = Jwk::new();
                    match ekp.public_key.key_type {
                        KeyType::X25519KeyAgreementKey2019 => {
                            e_key.crv = Some(String::from("ECDH-ES+A256KW"));
                            e_key.kid = Some(calc_kid(&self.id, &ekp.public_key.controller[0]));
                            e_key.add_other_header(String::from("x"), base64::encode(&ekp.public_key.public_key));
                        },
                        _ => return Err(Error::UnsupportedKeyType)
                    }
                    let mut jwe = Message::new();
                    jwe.jwm_header.kid = e_key.kid.clone();
                    jwe.jwm_header.alg = Some(String::from("ECDH-ES+A256KW"));
                    jwe.jwm_header.cty = Some(String::from("JWM"));
                    jwe.jwm_header.jwk = Some(e_key);
                    jwe.set_didcomm_header(m.get_didcomm_header().to_owned())
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
    pub fn receive_message(&self, msg_bytes: &[u8]) -> Result<Message, Error> {
        let jwe: Jwe = serde_json::from_slice(msg_bytes)?;
        if let Some(kp) = self.get_content_from_header(&jwe.to().to_vec()) {
            match kp {
                Content::KeyPair(unwrapped_kp) => {
                    Ok(Message::receive(
                        &String::from_utf8_lossy(msg_bytes),
                        &unwrapped_kp.private_key(),
                    )?)
                },
                _ => return Err(Error::ContentNotFound(jwe.to().iter().map(|s| s.to_owned()).collect::<String>()))
            }
        } else {
            Err(Error::DidcommError(didcomm_rs::Error::JweParseError))
        }
    }

    // helper method to parse keypair `Content` id from incomming `kid`
    fn get_content_from_header(&self, ids: &[String]) -> Option<Content> {
        for id in ids {
            if let Some(document) = resolve_any(id) {
                if let Some(controller) = document.find_public_key_controller_for_curve("X25519") {
                    match self.contents.get_by_controller(&controller) {
                        Some(v) => return Some(v.1.to_owned()),
                        None => continue
                    }
                } else { continue; }
            } else {
                continue;
            }
        }
        None
    }
}

// helper function to calculate `kid` JWK header based on:
// walled id + # + key controller
fn calc_kid(id: &str, cntrlr: &str) -> String {
    [id, cntrlr].join("#")
}

#[test]
fn send_receive_test() {
    // Arrange
    use base58::FromBase58;

    let m = Message::new()
        .from("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp")
        .to(&vec!("did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG", "did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf"))
        .as_jwe(&didcomm_rs::crypto::CryptoAlgorithm::XC20P);

    let mut alice_wallet = UnlockedWallet::new("alice");
    let alice_didkey_content = Content::KeyPair(KeyPair {
        public_key: PublicKeyInfo::new(KeyType::X25519KeyAgreementKey2019, &"7By6kV2t2d188odEM4ExAve1UithKT6dLva4dwsDT3ak".from_base58().unwrap()),
        private_key: "6QN8DfuN9hjgHgPvLXqgzqYE3jRRGRrmJQZkd5tL8paR".from_base58().unwrap()
    }.set_controller(vec!("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp".into())));
    let alice_import = alice_wallet.import_content(&alice_didkey_content);

    let mut bob_wallet = UnlockedWallet::new("bob");
    let bob_didkey_content = Content::KeyPair(KeyPair {
        public_key: PublicKeyInfo::new(KeyType::X25519KeyAgreementKey2019, &"FcoNC5NqP9CePWbhfz95iHaEsCjGkZUioK9Ck7Qiw286".from_base58().unwrap()),
        private_key: "HBTcN2MrXNRj9xF9oi8QqYyuEPv3JLLjQKuEgW9oxVKP".from_base58().unwrap()
    }.set_controller(vec!("did:key:z6MkjchhfUsD6mmvni8mCdXHw216Xrm9bQe2mBH1P5RDjVJG".into())));
    let bob_import = bob_wallet.import_content(&bob_didkey_content);

    // Act
    let alice_encrypted_message = alice_wallet.seal_encrypted(&serde_json::to_string(&m).unwrap());
    assert!(alice_encrypted_message.is_ok());

    let bob_received_message = bob_wallet.receive_message(&alice_encrypted_message.unwrap().as_bytes());

    // Assert
    assert!(alice_import.is_some());
    assert!(bob_import.is_some());
    assert!(bob_received_message.is_ok());
}
