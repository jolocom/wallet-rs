use super::encryption::unseal_box;
use super::public_key_info::{KeyType, PublicKeyInfo};
use serde::{Deserialize, Serialize};
use secp256k1::{Secp256k1, Message, SecretKey };
use ursa::{
    encryption::symm::prelude::*, kex::x25519::X25519Sha256, keys::{
        PrivateKey,
    },
    signatures::prelude::*,
};
use crypto::digest::Digest;
use crypto::sha3::Sha3;

#[derive(Serialize, Deserialize, Clone)]
pub struct KeyPair {
    #[serde(flatten)]
    pub public_key: PublicKeyInfo,
    private_key: PrivateKey,
}

impl KeyPair {
    pub fn random_pair(key_type: KeyType) -> Result<KeyPair, String> {
        match key_type {
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
                let secp_secret_key = SecretKey::from_slice(&self.private_key.0)
                    .map_err(|e| e.to_string())?;

                let mut hasher = Sha3::keccak256();
                hasher.input(data);
                let mut output = [0u8; 32];
                hasher.result(&mut output);

                let message = Message::from_slice(&output)
                    .map_err(|e| e.to_string())?;

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
