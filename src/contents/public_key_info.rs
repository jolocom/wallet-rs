use core::str::FromStr;
use serde::{Deserialize, Serialize};
use ursa::{encryption::symm::prelude::*, keys::PublicKey, signatures::prelude::*};

#[derive(Serialize, Deserialize, Clone)]
pub struct PublicKeyInfo {
    pub controller: Vec<String>,
    #[serde(rename = "type")]
    pub key_type: KeyType,
    pub public_key: PublicKey,
}

impl PublicKeyInfo {
    pub fn controller(self, controller: Vec<String>) -> Self {
        Self {
            controller: controller,
            ..self
        }
    }
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        match self.key_type {
            // default use xChaCha20Poly1905
            KeyType::X25519KeyAgreementKey2019 => todo!(),
            _ => Err("wrong key type".to_string()),
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
}

#[derive(Serialize, Deserialize, Clone, Copy)]
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

impl FromStr for KeyType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "JwsVerificationKey2020" => Ok(Self::JwsVerificationKey2020),
            "EcdsaSecp256k1VerificationKey2019" => Ok(Self::EcdsaSecp256k1VerificationKey2019),
            "Ed25519VerificationKey2018" => Ok(Self::Ed25519VerificationKey2018),
            "GpgVerificationKey2020" => Ok(Self::GpgVerificationKey2020),
            "RsaVerificationKey2018" => Ok(Self::RsaVerificationKey2018),
            "X25519KeyAgreementKey2019" => Ok(Self::X25519KeyAgreementKey2019),
            "SchnorrSecp256k1VerificationKey2019" => Ok(Self::SchnorrSecp256k1VerificationKey2019),
            "EcdsaSecp256k1RecoveryMethod2020" => Ok(Self::EcdsaSecp256k1RecoveryMethod2020),
            _ => Err("No Such Key Type".to_string()),
        }
    }
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
