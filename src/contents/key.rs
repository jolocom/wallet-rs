use serde::{Deserialize, Serialize};
use ursa::{
    keys::{PrivateKey, PublicKey},
    signatures::prelude::*,
};

#[derive(Serialize, Deserialize)]
pub struct Key {
    pub controller: Vec<String>,
    #[serde(rename = "type")]
    pub key_type: KeyType,
    #[serde(flatten)]
    pub public_key: PublicKey,
    #[serde(flatten)]
    private_key: Option<PrivateKey>,
}

impl Key {
    pub fn random_pair(key_type: KeyType) -> Result<Key, String> {
        match key_type {
            KeyType::Ed25519VerificationKey2018 => {
                let ed = Ed25519Sha512::new();
                let (pk, sk) = ed.keypair(None).map_err(|e| e.to_string())?;
                Ok(Key {
                    controller: vec![],
                    key_type: key_type,
                    public_key: pk,
                    private_key: Some(sk),
                })
            }
            KeyType::EcdsaSecp256k1VerificationKey2019 => {
                let scp = EcdsaSecp256k1Sha256::new();
                let (pk, sk) = scp.keypair(None).map_err(|e| e.to_string())?;
                Ok(Key {
                    controller: vec![],
                    key_type: key_type,
                    public_key: pk,
                    private_key: Some(sk),
                })
            }
            _ => Err("key type unsupported".to_string()),
        }
    }
    pub fn controller(self, controller: Vec<String>) -> Self {
        Key {
            controller: controller,
            ..self
        }
    }
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        match self.private_key {
            Some(k) => match self.key_type {
                KeyType::Ed25519VerificationKey2018 => {
                    let ed = Ed25519Sha512::new();
                    ed.sign(data, &k).map_err(|e| e.to_string())
                }
                KeyType::EcdsaSecp256k1VerificationKey2019 => {
                    let scp = EcdsaSecp256k1Sha256::new();
                    scp.sign(data, &k).map_err(|e| e.to_string())
                }
                _ => Err("wrong key type".to_string()),
            },
            None => Err("no private key".to_string()),
        }
    }
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, String> {
        match self.key_type {
            KeyType::Ed25519VerificationKey2018 => {
                let ed = Ed25519Sha512::new();
                ed.verify(data, signature, &self.public_key)
                    .map_err(|e| e.to_string())
            }
            KeyType::EcdsaSecp256k1VerificationKey2019 => {
                let scp = EcdsaSecp256k1Sha256::new();
                scp.verify(data, signature, &self.public_key)
                    .map_err(|e| e.to_string())
            }
            _ => Err("wrong key type".to_string()),
        }
    }
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        match self.private_key {
            Some(k) => match self.key_type {
                // default use xChaCha20Poly1905
                KeyType::X25519KeyAgreementKey2019 => todo!(),
                _ => Err("wrong key type".to_string()),
            },
            None => Err("no private key".to_string()),
        }
    }
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        match self.key_type {
            // default use xChaCha20Poly1905
            KeyType::X25519KeyAgreementKey2019 => todo!(),
            _ => Err("wrong key type".to_string()),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq)]
pub enum KeyType {
    JwsVerificationKey2020,
    EcdsaSecp256k1VerificationKey2019,
    Ed25519VerificationKey2018,
    GpgVerificationKey2020,
    RsaVerificationKey2018,
    X25519KeyAgreementKey2019,
    SchnorrSecp256k1VerificationKey2019,
    EcdsaSecp256k1RecoveryMethod2020,
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PublicKeyEncoding {
    // TODO, find a good JWK def crate
    // PublicKeyJwk,
    PublicKeyHex(String),
    PublicKeyBase64(String),
    PublicKeyBase58(String),
    PublicKeyMultibase(String),
    EthereumAddress(String),
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
