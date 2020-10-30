use super::encryption::{KEYSIZE, seal_box};
use core::str::FromStr;
use std::convert::TryInto;
use crypto_box::PublicKey;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use k256::ecdsa::{
    self,
    SigningKey,
    signature::Signer,
    recoverable
};
use wasm_bindgen::prelude::*;
use crate::Error;

/// Holds public information on key, controller and type of the key.
///
#[wasm_bindgen]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicKeyInfo {
    /// key controller information.
    pub controller: Box<[JsValue]>,
    #[serde(rename = "type")]
    /// variant of `KeyType` representing type of the key.
    pub key_type: KeyType,
    #[serde(rename = "publicKeyHex")]
    /// vector of bytes of public key.
    pub public_key: Vec<u8>,
}

impl PublicKeyInfo {
    /// Contstructor, which builds instance from `KeyType` and slice
    /// of bytes which are public key of type specified.
    // TODO: should this be checking if key matches len of declared type?
    ///
    /// # Parameters
    ///
    /// * kt - KeyType of provided key;
    /// * pk - public key as slice of bytes;
    ///
    /// # Examples
    /// ```
    /// # use crate::{
    /// #    universal_wallet::contents::public_key_info::{
    /// #               KeyType,
    /// #               PublicKeyInfo,
    /// #       },
    /// # };
    /// # fn test() {
    /// let pki = PublicKeyInfo::new(
    ///     KeyType::EcdsaSecp256k1VerificationKey2019,
    ///     &[0,0,0,0,0,0,0,0,0,0,0,0,0]);
    /// # }
    /// ```
    ///
    pub fn new(kt: KeyType, pk: &[u8]) -> Self {
        Self {
            controller: vec![],
            key_type: kt,
            public_key: pk.to_vec(),
        }
    }

    /// Sets controller property to provided value and returns updated struct.
    ///
    /// # Parameters
    ///
    /// * controller - `Vector` of `String`s to be set as new value.
    ///
    /// # Examples
    /// ```
    /// # use crate::{
    /// #    universal_wallet::contents::public_key_info::{
    /// #           KeyType,
    /// #           PublicKeyInfo,
    /// #       },
    /// # };
    /// # fn test() {
    /// let pki = PublicKeyInfo::new(KeyType::EcdsaSecp256k1VerificationKey2019,
    ///     &[0,0,0,0,0,0,0,0,0,0,0,0,0])
    ///     .controller(vec!("some new controller".into()));
    /// # }
    /// ```
    pub fn controller(self, controller: Vec<String>) -> Self {
        Self {
            controller: controller,
            ..self
        }
    }

    // TODO: should this cover all the key types?
    /// Encrypts message using own keys.
    ///
    /// # Parameters
    ///
    /// * data - message to be encrypted.
    /// * _aad - optional. not used ATM.
    ///
    /// # Examples
    /// ```
    /// # use crate::{
    /// #    universal_wallet::{
    /// #       contents::{
    /// #           public_key_info::{
    /// #               KeyType,
    /// #               PublicKeyInfo,
    /// #           },
    /// #           key_pair::KeyPair,
    /// #       },
    /// #   Error,
    /// #   }
    /// # };
    /// # fn test() -> Result<(), Error> {
    ///     let key_pair = KeyPair::random_pair(KeyType::X25519KeyAgreementKey2019)?;
    ///     let cipher_text = key_pair.public_key.encrypt(b"Super secret message", None)?;
    /// #   Ok(()) 
    /// # }
    pub fn encrypt(&self, data: &[u8], _aad: Option<&[u8]>) -> Result<Vec<u8>, Error> {
        match self.key_type {
            // default use xChaCha20Poly1905
            KeyType::X25519KeyAgreementKey2019 => {
                let pk: [u8; KEYSIZE] = self.public_key[..KEYSIZE]
                    .try_into()
                    .map_err(|_| Error::BoxToSmall)?;
                seal_box(data, &PublicKey::from(pk))
            }
            _ => Err(Error::WrongKeyType),
        }
    }

    /// Verifies validity of the signature provided.
    ///
    /// # Parameters
    ///
    /// * data - original message.
    /// * signature - generated by signing data.
    ///
    /// # Examples
    /// ```
    /// # use crate::{
    /// #    universal_wallet::{
    /// #       contents::{
    /// #           public_key_info::{
    /// #               KeyType,
    /// #               PublicKeyInfo,
    /// #           },
    /// #           key_pair::KeyPair,
    /// #       },
    /// #   Error,
    /// #   }
    /// # };
    /// # fn test() -> Result<(), Error> {
    ///     let key_pair = KeyPair::random_pair(KeyType::X25519KeyAgreementKey2019)?;
    ///     let signature = key_pair.sign(b"Not so secret stuff")?;
    ///     assert!(key_pair.public_key.verify(b"Not so secret stuff", &signature)?);
    /// #   Ok(()) 
    /// # }
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, Error> {
        match self.key_type {
            KeyType::Ed25519VerificationKey2018 => {
                use ed25519_dalek::{PublicKey, Verifier, Signature};
                let pk = PublicKey::from_bytes(&self.public_key)
                    .map_err(|e| Error::Other(Box::new(e)))?;
                if signature.len() != 64 {
                    return Err(Error::WrongKeyLength);
                }
                let owned_signature = signature.to_owned();
                let array_signature = array_ref!(owned_signature, 0, 64).to_owned();
                let signature = Signature::from(array_signature);

                Ok(pk.verify(data, &signature).is_ok())
            },
            KeyType::EcdsaSecp256k1VerificationKey2019 => {
                use k256::ecdsa::{Signature, VerifyKey, signature::Verifier};
                let vk = VerifyKey::new(array_ref!(&self.public_key, 0, 32))
                    .map_err(|e| Error::EcdsaCryptoError(e))?;
                let s1: [u8; 32] = array_ref!(signature, 0, 32).to_owned();
                let s2: [u8; 32] = array_ref!(signature, 32, 32).to_owned();
                let sign = Signature::from_scalars(s1, s2)
                    .map_err(|e| Error::EdCryptoError(e))?;
                Ok(vk.verify(data, &sign).is_ok())
            },
            KeyType::EcdsaSecp256k1RecoveryMethod2020 => {
                let s1: [u8; 32] = array_ref!(signature, 0, 32).to_owned();
                let s2: [u8; 32] = array_ref!(signature, 32, 32).to_owned();
                let rs = ecdsa::Signature::from_scalars(s1, s2)
                    .map_err(|e| Error::EdCryptoError(e))?;
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

/// Lists all supported* keys.
/// TODO: find links to all the key specs.
#[wasm_bindgen]
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
pub enum KeyType {
    /// [W3C](https://w3c-ccg.github.io/ld-cryptosuite-registry/#jsonwebsignature2020{
    JwsVerificationKey2020,
    /// [W3C](https://w3c-ccg.github.io/ld-cryptosuite-registry/#ecdsasecp256k1signature2019)
    EcdsaSecp256k1VerificationKey2019,
    /// [W3C](https://w3c-ccg.github.io/ld-cryptosuite-registry/#ed25519)
    Ed25519VerificationKey2018,
    /// [W3C](https://w3c-ccg.github.io/ld-cryptosuite-registry/#gpgsignature2020)
    GpgVerificationKey2020,
    /// [W3C](https://w3c-ccg.github.io/ld-cryptosuite-registry/#rsasignature2018)
    RsaVerificationKey2018,
    X25519KeyAgreementKey2019,
    SchnorrSecp256k1VerificationKey2019,
    /// [W3C](https://w3c-ccg.github.io/ld-cryptosuite-registry/#ecdsasecp256k1recoverysignature2020)
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

/// Defines encoding for public keys.
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
    _v: u8,
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
