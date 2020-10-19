use super::encryption::{KeySize, seal_box};
use core::str::FromStr;
use std::convert::TryInto;
use crypto_box::PublicKey;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use k256::ecdsa::{
    SigningKey,
    Signature,
    signature::Signer,
    recoverable
};
use crate::Error;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicKeyInfo {
    pub controller: Vec<String>,
    #[serde(rename = "type")]
    pub key_type: KeyType,
    #[serde(rename = "publicKeyHex")]
    pub public_key: Vec<u8>,
}

impl PublicKeyInfo {
    pub fn new(kt: KeyType, pk: &[u8]) -> Self {
        Self {
            controller: vec![],
            key_type: kt,
            public_key: pk.to_vec(),
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
                let pk: [u8; KeySize] = self.public_key[..KeySize]
                    .try_into()
                    .map_err(|_| Error::BoxToSmall)?;
                seal_box(data, &PublicKey::from(pk))
            }
            _ => Err(Error::WrongKeyType),
        }
    }

    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, Error> {
        match self.key_type {
            KeyType::Ed25519VerificationKey2018 => {
                use ed25519_dalek::{PublicKey, Verifier, Signature};
                let pk = PublicKey::from_bytes(&self.public_key)
                    .map_err(|e| Error::Other(Box::new(e)))?;
                if signature.len() != 64 {
                    return Err(Error::WrongKeyLength);
                }
                let signature = Signature::from(array_ref!(signature.to_owned(), 0, 64).to_owned());

                Ok(pk.verify(data, &signature).is_ok())
            },
            KeyType::EcdsaSecp256k1VerificationKey2019 => {
                use k256::ecdsa::{VerifyKey, signature::Verifier};
                let vk = VerifyKey::new(array_ref!(&self.public_key, 0, 32))
                    .map_err(|e| Error::EcdsaCryptoError(e))?;
                Ok(vk.verify(data, signature).is_ok())
            },
            KeyType::EcdsaSecp256k1RecoveryMethod2020 => {
                use k256::ecdsa::{self, recoverable};
                // TODO find an appropriate constructor
                let rs = ecdsa::Signature{bytes: generic_array::GenericArray::from_slice(signature).to_owned()};
                let recovered_signature = recoverable::Signature::from_trial_recovery(
                    &ecdsa::VerifyKey::new(&self.public_key).map_err(|e| Error::EcdsaCryptoError(e))?,
                    data,
                    &rs
                ).map_err(|oe| Error::EcdsaCryptoError(oe))?;

                let recovered_key = recovered_signature.recover_verify_key(data)
                    .map_err(|e| Error::EcdsaCryptoError(e))?;

                let our_key = ecdsa::VerifyKey::new(&self.public_key).map_err(|e| Error::EcdsaCryptoError(e))?;

                Ok(our_key == recovered_key)
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

// TODO: find out if they still required by any consumer
// cleanup if not...

pub fn to_recoverable_signature(
    v: u8,
    r: &[u8; 32],
    s: &[u8; 32],
) -> Result<recoverable::Signature, Error> {
    let s_key = SigningKey::random(OsRng);
    let mut data = [0u8; 64];
    data[0..32].copy_from_slice(r);
    data[32..64].copy_from_slice(s);

    Ok(s_key.sign(&data))
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
