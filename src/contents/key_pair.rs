use super::encryption::unseal_box;
use super::public_key_info::{KeyType, PublicKeyInfo};
use crate::Error;
use crypto_box::SecretKey;
use ed25519_dalek::Keypair;
use k256::ecdsa::{recoverable, signature::Signer, Signature, SigningKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

/// Serializable struct to hold pair of public and private keys.
/// Universal for any key types as keys stored as bytes.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyPair {
    /// Public key is instance of `PublicKeyInfo` struct.
    #[serde(flatten)]
    pub public_key: PublicKeyInfo,
    /// Private key in form of vector of bytes.
    #[serde(rename = "privateKeyHex", with = "hex")]
    pub(crate) private_key: Vec<u8>,
}

impl KeyPair {
    /// Constructs set of keys from private key.
    /// Public key generated in the method from private key provided.
    ///
    /// # Arguments
    ///
    /// *`key_type` - variont of `KeyType` enum.
    /// Currently supportet key types are:
    /// `Ed25519VerificationKey2018` [W3C](https://w3c-ccg.github.io/ld-cryptosuite-registry/#ed25519)<br>
    /// `EcdsaSecp256k1VerificationKey2019` [W3C](https://w3c-ccg.github.io/ld-cryptosuite-registry/#ecdsasecp256k1signature2019)<br>
    /// `EcdsaSecp256k1RecoveryMethod2020` [W3C](https://w3c-ccg.github.io/ld-cryptosuite-registry/#ecdsasecp256k1recoverysignature2020)<br>
    //  TODO: find proper link for x25519 key
    /// `X25519KeyAgreementKey2019` [W3C](https://www.w3.org/TR/did-core/#key-types-and-formats)<br>
    ///
    pub fn new(key_type: KeyType, priv_key: &Vec<u8>) -> Result<Self, Error> {
        let (pk, sk) = match key_type {
            KeyType::Ed25519VerificationKey2018 => {
                let sk = ed25519_dalek::SecretKey::from_bytes(priv_key)
                    .map_err(|e| Error::EdCryptoError(e))?;
                let pk: ed25519_dalek::PublicKey = (&sk).into();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            KeyType::EcdsaSecp256k1VerificationKey2019
            | KeyType::EcdsaSecp256k1RecoveryMethod2020 => {
                let sign_key = SigningKey::from_bytes(priv_key)?;
                let verify_key = sign_key.verifying_key();
                (
                    verify_key.to_bytes().to_vec(),
                    sign_key
                        .to_bytes()
                        .iter_mut()
                        .map(|v| *v)
                        .collect::<Vec<u8>>(),
                )
            }
            KeyType::X25519KeyAgreementKey2019 => {
                let secret = StaticSecret::from(array_ref!(priv_key, 0, 32).to_owned());
                let pk = PublicKey::from(&secret).to_bytes();
                (pk.to_vec(), secret.to_bytes().to_vec())
            }
            _ => return Err(Error::UnsupportedKeyType),
        };

        Ok(KeyPair {
            public_key: PublicKeyInfo {
                controller: vec![],
                key_type,
                public_key: pk,
            },
            private_key: sk,
        })
    }

    /// Generates random `KeyPair` of specified `KeyType` type.
    ///
    /// *`key_type` - variont of `KeyType` enum.
    ///
    /// # Examples
    ///
    /// ```
    /// # use crate::{
    /// #    universal_wallet::{
    /// #       Error,
    /// #       contents::{
    /// #           public_key_info::KeyType,
    /// #           key_pair::KeyPair,
    /// #       },
    /// #    },
    /// # };
    /// # fn rkp() -> Result<(), Error> {
    ///     let key_pair = KeyPair::random_pair(KeyType::EcdsaSecp256k1VerificationKey2019)?;
    /// #   Ok(())
    /// # }
    /// ```
    ///
    pub fn random_pair(key_type: KeyType) -> Result<KeyPair, Error> {
        let (pk, sk) = match key_type {
            KeyType::X25519KeyAgreementKey2019 => {
                let sk = StaticSecret::new(OsRng);
                (
                    PublicKey::from(&sk).as_bytes().to_vec(),
                    sk.to_bytes().to_vec(),
                )
            }
            KeyType::Ed25519VerificationKey2018 => {
                let kp = Keypair::generate(&mut OsRng);
                (kp.public.as_bytes().to_vec(), kp.secret.as_bytes().to_vec())
            }
            KeyType::EcdsaSecp256k1VerificationKey2019
            | KeyType::EcdsaSecp256k1RecoveryMethod2020 => {
                let sign_key = SigningKey::random(&mut rand::rngs::OsRng);
                (
                    sign_key.verifying_key().to_bytes().to_vec(),
                    sign_key.to_bytes().to_vec(),
                )
            }
            KeyType::Bls12381G1Key2020 => {
                use signature_bls::{PublicKeyVt, SecretKey};
                let sk = SecretKey::random(&mut rand::rngs::OsRng)
                    .ok_or(Error::BlsCryptoError("failed to generate random SK".into()))?;
                let pk = PublicKeyVt::from(&sk);
                (pk.to_bytes().to_vec(), sk.to_bytes().to_vec())
            }
            KeyType::Bls12381G2Key2020 => {
                use signature_bls::{PublicKey, SecretKey};
                let sk = SecretKey::random(&mut rand::rngs::OsRng)
                    .ok_or(Error::BlsCryptoError("failed to generate random SK".into()))?;
                let pk = PublicKey::from(&sk);
                (pk.to_bytes().to_vec(), sk.to_bytes().to_vec())
            }
            _ => return Err(Error::UnsupportedKeyType),
        };

        Ok(KeyPair {
            public_key: PublicKeyInfo {
                controller: vec![],
                key_type,
                public_key: pk,
            },
            private_key: sk,
        })
    }

    /// Updates `.controller` property to provided value.
    ///
    /// *`controller` - collection of controller `String`s.
    ///
    pub fn set_controller(self, controller: Vec<String>) -> Self {
        KeyPair {
            public_key: self.public_key.controller(controller),
            ..self
        }
    }

    /// Signst provided message with the key from `KeyType` set during `KeyPair` creation.
    ///
    /// *`data` - message slice to be signed
    ///
    /// Returns `Result` of generated signature in form of `Vec<u8>` or `Error`.
    ///
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        match self.public_key.key_type {
            KeyType::Ed25519VerificationKey2018 => {
                let mut pk = self.public_key.public_key.clone();
                let mut spk = self.private_key.clone();
                spk.append(&mut pk);
                let kp = Keypair::from_bytes(&spk.as_ref()).map_err(|e| Error::EdCryptoError(e))?;
                let sig = kp.sign(data);
                Ok(sig.to_bytes().into())
            }
            KeyType::EcdsaSecp256k1VerificationKey2019 => {
                let sign_key = SigningKey::from_bytes(&self.private_key)?;
                let signature: Signature = sign_key.sign(data);
                Ok(signature.as_ref().to_vec())
            }
            KeyType::EcdsaSecp256k1RecoveryMethod2020 => {
                let sign_key = SigningKey::from_bytes(&self.private_key[..])?;
                // WARN: Signature type must be annotated to be recoverable!
                let signature: recoverable::Signature = sign_key.sign(data);
                Ok(signature.as_ref().to_vec())
            }
            KeyType::Bls12381G2Key2020 => {
                use signature_bls::{SecretKey, Signature};
                let sk = SecretKey::from_bytes(array_ref!(&self.private_key, 0, 32)).unwrap();
                let sig = Signature::new(&sk, data)
                    .ok_or(Error::BlsCryptoError("payload signing failed".into()))?;
                Ok(sig.to_bytes().to_vec())
            }
            KeyType::Bls12381G1Key2020 => {
                use signature_bls::{SecretKey, SignatureVt};
                let sk = SecretKey::from_bytes(array_ref!(&self.private_key, 0, 32)).unwrap();
                let sig = SignatureVt::new(&sk, data)
                    .ok_or(Error::BlsCryptoError("payload signing failed".into()))?;
                Ok(sig.to_bytes().to_vec())
            }
            _ => Err(Error::WrongKeyType),
        }
    }

    /// Decrypts cipher data using current private key.
    ///
    /// *`data` - cipher to be derypted.
    ///
    /// Returns `Result` of raw representation of the data in form of `Vec<u8>` or
    ///     `Error` indication failure.
    ///
    pub fn decrypt(&self, data: &[u8], _aad: Option<&[u8]>) -> Result<Vec<u8>, Error> {
        match self.public_key.key_type {
            // default use xChaCha20Poly1905 with x25519 key agreement
            KeyType::X25519KeyAgreementKey2019 => unseal_box(
                data,
                &SecretKey::from(array_ref!(&self.private_key, 0, 32).to_owned()),
            ),
            _ => Err(Error::WrongKeyType),
        }
    }

    /// Performs ECDH key agreement
    ///
    /// *`pk` - public key to perform agreement with
    ///
    /// Returns `Result` of shared secret in `Vec<u8>` form`
    pub fn ecdh_key_agreement(&self, pk: &[u8]) -> Result<Vec<u8>, Error> {
        match self.public_key.key_type {
            KeyType::X25519KeyAgreementKey2019 => Ok(StaticSecret::from(
                array_ref!(&self.private_key, 0, 32).to_owned(),
            )
            .diffie_hellman(&PublicKey::from(array_ref!(pk, 0, 32).to_owned()))
            .to_bytes()
            .into()),
            _ => Err(Error::WrongKeyType),
        }
    }

    /// Returns `Clone`d instance of `PublicKeyInfo` from own `public_key` property.
    pub fn get_public_key(&self) -> PublicKeyInfo {
        self.public_key.clone()
    }

    /// Returns `Clone`d instance of `Vec<u8>` from own private key.
    pub fn private_key(&self) -> Vec<u8> {
        self.private_key.clone()
    }
}

/// This `enum` indicates encoding for each Private Key
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PrivateKeyEncoding {
    // PrivateKeyJwk,
    PrivateKeyHex(String),
    PrivateKeyBase64(String),
    PrivateKeyBase58(String),
    PrivateKeyMultibase(String),
    PrivateKeyWebKms(String),
    PrivateKeySecureEnclave(String),
    PrivateKeyFromSeed { path: String, seed_ref: String },
}

#[test]
fn key_pair_new_ed25519() {
    // Test vector from https://fossies.org/linux/tor/src/test/ed25519_vectors.inc
    let test_sk =
        hex::decode("26c76712d89d906e6672dafa614c42e5cb1caac8c6568e4d2493087db51f0d36").unwrap();
    let expected_pk =
        hex::decode("c2247870536a192d142d056abefca68d6193158e7c1a59c1654c954eccaff894").unwrap();

    let key_entry = KeyPair::new(KeyType::Ed25519VerificationKey2018, &test_sk).unwrap();

    assert!(key_entry.public_key.key_type == KeyType::Ed25519VerificationKey2018);
    assert_eq!(key_entry.public_key.controller, Vec::<String>::new());
    assert_eq!(key_entry.public_key.public_key, expected_pk);
    assert_eq!(
        [
            &key_entry.private_key[..],
            &key_entry.public_key.public_key[..]
        ]
        .concat(),
        [&test_sk[..], &expected_pk[..]].concat()
    )
}

#[test]
fn keccak256_correct_output() {
    use blake2::Digest;
    use sha3::Keccak256;
    let input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let mut hasher = Keccak256::new();
    hasher.update(input.as_bytes());
    let output = hasher.finalize();
    assert_eq!(
        hex::encode(output),
        "45d3b367a6904e6e8d502ee04999a7c27647f91fa845d456525fd352ae3d7371"
    );
}

#[test]
fn key_pair_new_ecdsa_secp256k1() {
    // Self generated test vector.
    let test_sk =
        hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
    let expected_pk =
        hex::decode("03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd").unwrap();

    let key_entry = KeyPair::new(KeyType::EcdsaSecp256k1VerificationKey2019, &test_sk).unwrap();

    assert!(key_entry.public_key.key_type == KeyType::EcdsaSecp256k1VerificationKey2019);
    assert_eq!(key_entry.public_key.controller, Vec::<String>::new());
    assert_eq!(key_entry.private_key, test_sk);
    assert_eq!(key_entry.public_key.public_key, expected_pk);
}

#[test]
fn key_pair_new_ecdsa_x25519() -> Result<(), Error> {
    // Test vector from https://tools.ietf.org/html/rfc7748#section-6.1
    let test_sk =
        hex::decode("a8abababababababababababababababababababababababababababababab6b").unwrap();
    let expected_pk =
        hex::decode("e3712d851a0e5d79b831c5e34ab22b41a198171de209b8b8faca23a11c624859").unwrap();

    let key_entry = KeyPair::new(KeyType::X25519KeyAgreementKey2019, &test_sk)?;

    assert!(key_entry.public_key.key_type == KeyType::X25519KeyAgreementKey2019);
    assert_eq!(key_entry.public_key.controller, Vec::<String>::new());
    assert_eq!(key_entry.private_key, test_sk);
    assert_eq!(key_entry.public_key.public_key, expected_pk);
    Ok(())
}

#[test]
fn ecdh_test_1() -> Result<(), Error> {
    // test vector from https://tools.ietf.org/html/rfc7748#section-5.2
    let sk =
        hex::decode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4").unwrap();

    let pk =
        hex::decode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c").unwrap();

    let ak =
        hex::decode("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552").unwrap();

    let test_kp = KeyPair::new(KeyType::X25519KeyAgreementKey2019, &sk)?;

    assert_eq!(test_kp.ecdh_key_agreement(&pk)?, ak);
    Ok(())
}

#[test]
fn ecdh_test_2() -> Result<(), Error> {
    // test vector from https://tools.ietf.org/html/rfc7748#section-5.2
    let sk =
        hex::decode("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d").unwrap();

    let pk =
        hex::decode("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493").unwrap();

    let ak =
        hex::decode("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957").unwrap();

    let test_kp = KeyPair::new(KeyType::X25519KeyAgreementKey2019, &sk)?;

    assert_eq!(test_kp.ecdh_key_agreement(&pk)?, ak);
    Ok(())
}

#[test]
fn key_deser() -> Result<(), Error> {
    let content = r#"{"controller":["ecdh_key"],"type":"X25519KeyAgreementKey2019","publicKeyHex":"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a","privateKeyHex":"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"}"#;
    let kp: KeyPair = serde_json::from_str(content)?;

    assert_eq!(
        kp.private_key,
        hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").unwrap()
    );
    assert_eq!(
        kp.public_key.public_key,
        hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a").unwrap()
    );
    assert_eq!(kp.public_key.key_type, KeyType::X25519KeyAgreementKey2019);
    assert_eq!(kp.public_key.controller, vec!["ecdh_key".to_string()]);

    Ok(())
}
