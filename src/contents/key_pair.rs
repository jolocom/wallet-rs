use super::public_key_info::{KeyType, PublicKeyInfo};
use serde::{Deserialize, Serialize};
use ursa::{encryption::symm::prelude::*, keys::PrivateKey, signatures::prelude::*};

#[derive(Serialize, Deserialize, Clone)]
pub struct KeyPair {
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
            _ => Err("wrong key type".to_string()),
        }
    }
    pub fn decrypt(&self, data: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>, String> {
        match self.public_key.key_type {
            // default use xChaCha20Poly1905
            KeyType::X25519KeyAgreementKey2019 => todo!(),
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
