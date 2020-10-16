use super::encryption::seal_box;
use core::str::FromStr;
use k256::{
    EncodedPoint,
    ecdsa::{
        recoverable,
        SigningKey,
        VerifyKey,
    },
};
use serde::{Deserialize, Serialize};
use chacha20poly1305::{
    ChaCha20Poly1305,
    Key,
};
use x25519_dalek::X25519_BASEPOINT_BYTES;
use ed25519_dalek::{
    Verifier,
    PublicKey,
};
use sha3::{Digest, Keccak256};
use crate::Error;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicKeyInfo {
    pub controller: Vec<String>,
    #[serde(rename = "type")]
    pub key_type: KeyType,
    #[serde(rename = "publicKeyHex")]
    pub public_key: Key,
}

impl PublicKeyInfo {
    pub fn new(kt: KeyType, pk: &[u8]) -> Self {
        Self {
            controller: vec![],
            key_type: kt,
            public_key: Key::new(pk.to_vec()),
        }
    }

    pub fn controller(self, controller: Vec<String>) -> Self {
        Self {
            controller: controller,
            ..self
        }
    }

    pub fn encrypt(&self, data: &[u8], _aad: &[u8]) -> Result<Vec<u8>, Error> {
        match self.key_type {
            // default use xChaCha20Poly1905
            KeyType::X25519KeyAgreementKey2019 => {
                // is this really what we want? 
                seal_box::<X25519_BASEPOINT_BYTES, ChaCha20Poly1305>(data, &self.public_key)
            }
            _ => Err(Error::WrongKeyType),
        }
    }

    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, Error> {
        //&self.public_key.verify();
        match self.key_type {
            KeyType::Ed25519VerificationKey2018 => {
                let pk = PublicKey::from_bytes(&self.public_key)
                    .map_err(|e| Error::Other(e))?;
                Ok(match pk.verify(data, signature) {
                    Ok(()) => true,
                    Err(_) => false,
                })
            },
            KeyType::EcdsaSecp256k1VerificationKey2019 => {
                Ok(match VerifyKey::from(&self.public_key)
                    .verify(data, signature) {
                        Ok(()) => true,
                        Err(_) => false,
                    })
            },
            KeyType::EcdsaSecp256k1RecoveryMethod2020 => {
                let signing_key = SigningKey::from(&self.public_key);
                let verify_key = signing_key.verify_key();
                let recovered_key = signature.recover_verify_key_from_digest(signature)?;

                Ok(signing_key == recovered_key)
            }
            _ => Err(Error::WrongKeyType),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
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
) -> Result<recoverable::Signature, Error> {
    let s_key = SigningKey::from(v);
    let mut data = [0u8; 64];
    data[0..32].copy_from_slice(r);
    data[32..64].copy_from_slice(s);

    Ok(s_key.sign(data))
}

pub fn parse_concatenated(signature: &[u8]) -> Result<recoverable::Signature, Error> {
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
