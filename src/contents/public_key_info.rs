use super::encryption::seal_box;
use core::str::FromStr;
use serde::{Deserialize, Serialize};
use secp256k1::{Secp256k1, Message, recovery::{RecoverableSignature }};
use ursa::{
    encryption::symm::prelude::*, kex::x25519::X25519Sha256, keys::PublicKey,
    signatures::prelude::*,
};

use crypto::digest::Digest;
use crypto::sha3::Sha3;

#[derive(Serialize, Deserialize, Clone)]
pub struct PublicKeyInfo {
    pub controller: Vec<String>,
    #[serde(rename = "type")]
    pub key_type: KeyType,
    #[serde(rename = "publicKeyHex")]
    pub public_key: PublicKey,
}

impl PublicKeyInfo {
    pub fn new(kt: KeyType, pk: &[u8]) -> Self {
        Self {
            controller: vec![],
            key_type: kt,
            public_key: PublicKey(pk.to_vec()),
        }
    }

    pub fn controller(self, controller: Vec<String>) -> Self {
        Self {
            controller: controller,
            ..self
        }
    }

    pub fn encrypt(&self, data: &[u8], _aad: &[u8]) -> Result<Vec<u8>, String> {
        match self.key_type {
            // default use xChaCha20Poly1905
            KeyType::X25519KeyAgreementKey2019 => {
                seal_box::<X25519Sha256, XChaCha20Poly1305>(data, &self.public_key)
            }
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

            KeyType::EcdsaSecp256k1RecoveryMethod2020 => {
                let scp = Secp256k1::new();

                let mut output = [0u8; 32];
                let mut hasher = Sha3::keccak256();
                hasher.input(data);
                hasher.result(&mut output);

                let message = Message::from_slice(&output)
                    .or_else(|e| return Err(e.to_string()))?;

                let signature = parse_concatenated(&signature)?;

                let signing_key = scp.recover(&message, &signature)
                    .or_else(|e| return Err(e.to_string()))?;

                let our_key = secp256k1::PublicKey::from_slice(&self.public_key.0)
                    .or_else(|e| return Err(e.to_string()))?;
                // println!("{:?}", signing_key);
                // println!("{:?}", our_key);
                Ok(signing_key == our_key)
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

pub fn to_recoverable_signature(
    v: u8,
    r: &[u8; 32],
    s: &[u8; 32],
) -> Result<secp256k1::recovery::RecoverableSignature, String> {
    let rec_id = secp256k1::recovery::RecoveryId::from_i32(v as i32)
        .map_err(|_| "Failed to read the recovery bit")?;

    let mut data = [0u8; 64];
    data[0..32].copy_from_slice(r);
    data[32..64].copy_from_slice(s);

    Ok(secp256k1::recovery::RecoverableSignature::from_compact(&data, rec_id).map_err(|_| "Failed to parse signature")?)
}

pub fn parse_concatenated(signature: &[u8]) -> Result<RecoverableSignature, String> {
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    let v = signature[64];

    r.copy_from_slice(&signature[..32]);
    s.copy_from_slice(&signature[32..64]);

    println!("{:?}", signature);
    println!("{:?}", r);
    println!("{:?}", s);
    println!("{:?}", v);

    to_recoverable_signature(v, &r, &s)
}
