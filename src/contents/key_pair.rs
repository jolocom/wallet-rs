use super::encryption::unseal_box;
use super::public_key_info::{KeyType, PublicKeyInfo};
use crypto::digest::Digest;
use crypto::sha3::Sha3;
use secp256k1::{Message, Secp256k1};
use serde::{Deserialize, Serialize};
use ursa::{
    encryption::symm::prelude::*, kex::x25519::X25519Sha256, kex::KeyExchangeScheme, keys::{
        PrivateKey, KeyGenOption
    },
    signatures::prelude::*,
};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyPair {
    #[serde(flatten)]
    pub public_key: PublicKeyInfo,
    pub private_key: PrivateKey,
}

impl KeyPair {
    pub fn new(key_type: KeyType, priv_key: &Vec<u8>) -> Result<KeyPair, String> {
        let (pk, sk) = match key_type {
            KeyType::Ed25519VerificationKey2018 => Ed25519Sha512::expand_keypair(&priv_key)
                .map_err(|e| e.to_string())?,

            KeyType::EcdsaSecp256k1VerificationKey2019 => EcdsaSecp256k1Sha256::new().keypair(
                Some(KeyGenOption::FromSecretKey(PrivateKey(priv_key.clone()))))
                .map_err(|e| e.to_string())?,
            _ => return Err("key type unsupported".to_string())
        };

        Ok(KeyPair {
            public_key: PublicKeyInfo {
                controller: vec![],
                key_type: key_type,
                public_key: pk,
            },
            private_key: sk
        })
    }

    pub fn random_pair(key_type: KeyType) -> Result<KeyPair, String> {
        match key_type {
            KeyType::X25519KeyAgreementKey2019 => {
                let x = X25519Sha256::new();
                let (pk, sk) = x.keypair(None).map_err(|e| e.to_string())?;
                Ok(KeyPair {
                    public_key: PublicKeyInfo {
                        controller: vec![],
                        key_type: key_type,
                        public_key: pk,
                    },
                    private_key: sk,
                })
            }
            KeyType::Ed25519VerificationKey2018 => {
                let ed = Ed25519Sha512::new();
                let (pk, sk) = ed.keypair(None).map_err(|e| e.to_string())?;
                Ok(KeyPair {
                    public_key: PublicKeyInfo {
                        controller: vec![],
                        key_type: key_type,
                        public_key: pk,
                    },
                    private_key: sk,
                })
            }
            KeyType::EcdsaSecp256k1VerificationKey2019 => {
                let scp = EcdsaSecp256k1Sha256::new();
                let (pk, sk) = scp.keypair(None).map_err(|e| e.to_string())?;
                Ok(KeyPair {
                    public_key: PublicKeyInfo {
                        controller: vec![],
                        key_type: key_type,
                        public_key: pk,
                    },
                    private_key: sk,
                })
            }
            KeyType::EcdsaSecp256k1RecoveryMethod2020 => {
                let scp = EcdsaSecp256k1Sha256::new();
                let (pk, sk) = scp.keypair(None).map_err(|e| e.to_string())?;
                Ok(KeyPair {
                    public_key: PublicKeyInfo {
                        controller: vec![],
                        key_type: key_type,
                        public_key: pk,
                    },
                    private_key: sk,
                })
            }
            _ => Err("key type unsupported".to_string()),
        }
    }
    pub fn controller(self, controller: Vec<String>) -> Self {
        KeyPair {
            public_key: self.public_key.controller(controller),
            ..self
        }
    }
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        match self.public_key.key_type {
            KeyType::Ed25519VerificationKey2018 => {
                let ed = Ed25519Sha512::new();
                ed.sign(data, &self.private_key).map_err(|e| e.to_string())
            }
            KeyType::EcdsaSecp256k1VerificationKey2019 => {
                let scp = EcdsaSecp256k1Sha256::new();
                scp.sign(data, &self.private_key).map_err(|e| e.to_string())
            }
            KeyType::EcdsaSecp256k1RecoveryMethod2020 => {
                let scp = Secp256k1::new();

                let secp_secret_key = secp256k1::SecretKey::from_slice(&self.private_key.0)
                    .map_err(|e| e.to_string())?;

                let mut hasher = Sha3::keccak256();
                hasher.input(data);
                let mut output = [0u8; 32];
                hasher.result(&mut output);

                let message = Message::from_slice(&output).map_err(|e| e.to_string())?;

                let sig = scp.sign_recoverable(&message, &secp_secret_key);
                let (rec_id, rs) = sig.serialize_compact();

                let rec_bit = rec_id.to_i32() as u8;

                let mut ret = rs.to_vec();
                ret.push(rec_bit);

                Ok(ret)
            }
            _ => Err("wrong key type".to_string()),
        }
    }
    pub fn decrypt(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        match self.public_key.key_type {
            // default use xChaCha20Poly1905 with x25519 key agreement
            KeyType::X25519KeyAgreementKey2019 => unseal_box::<X25519Sha256, XChaCha20Poly1305>(
                data,
                &self.public_key.public_key,
                &self.private_key,
            ),
            _ => Err("wrong key type".to_string()),
        }
    }
    pub fn clean(&self) -> PublicKeyInfo {
        self.public_key.clone()
    }
}

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
fn key_pair_new_ed25519 () {
    // Test vector from https://fossies.org/linux/tor/src/test/ed25519_vectors.inc
    let test_sk = hex::decode("26c76712d89d906e6672dafa614c42e5cb1caac8c6568e4d2493087db51f0d36").unwrap();
    let expected_pk = hex::decode("c2247870536a192d142d056abefca68d6193158e7c1a59c1654c954eccaff894").unwrap();

    let key_entry = KeyPair::new(KeyType::Ed25519VerificationKey2018, &test_sk).unwrap();

    assert!(key_entry.public_key.key_type == KeyType::Ed25519VerificationKey2018);
    assert_eq!(key_entry.public_key.controller, Vec::<String>::new());
    assert_eq!(key_entry.public_key.public_key.0, expected_pk);
    assert_eq!(key_entry.private_key.0, [&test_sk[..], &expected_pk[..]].concat())
}

#[test]
fn key_pair_new_ecdsa_secp256k1() {
    // Self generated test vector.
    let test_sk = hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap();
    let expected_pk = hex::decode("03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd").unwrap();

    let key_entry = KeyPair::new(KeyType::EcdsaSecp256k1VerificationKey2019, &test_sk).unwrap();

    assert!(key_entry.public_key.key_type == KeyType::EcdsaSecp256k1VerificationKey2019);
    assert_eq!(key_entry.public_key.controller, Vec::<String>::new());
    assert_eq!(key_entry.private_key.0, test_sk);
    assert_eq!(key_entry.public_key.public_key.0, expected_pk);
}
