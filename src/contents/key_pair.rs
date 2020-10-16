use super::encryption::unseal_box;
use super::public_key_info::{KeyType, PublicKeyInfo};
use k256::{
    ecdsa::{
        SigningKey,
        VerifyKey,
        signature::Signer,
        recoverable,
    },
    SecretKey,
};
use serde::{Deserialize, Serialize};
use chacha20poly1305::{
    ChaCha20Poly1305,
};
use x25519_dalek::{
    x25519,
    PublicKey,
    EphemeralSecret,
    X25519_BASEPOINT_BYTES,
};
use ed25519_dalek::Keypair;
use sha3::{Digest, Keccak256};
use rand_core::OsRng;
use crate::Error;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyPair {
    #[serde(flatten)]
    pub public_key: PublicKeyInfo,
    pub private_key: SecretKey,
}

impl KeyPair {
    pub fn new(key_type: KeyType, priv_key: &Vec<u8>) -> Result<KeyPair, Error> {
        let (pk, sk) = match key_type {
            KeyType::Ed25519VerificationKey2018 => {
                // Is this correct?
                Keypair::from_bytes(priv_key)
                // Ed25519Sha512::expand_keypair(&priv_key).map_err(|e| Error::UrsaCryptoError(e))?
            },
            KeyType::EcdsaSecp256k1VerificationKey2019
            | KeyType::EcdsaSecp256k1RecoveryMethod2020 => {
                let sign_key = SigningKey::from(priv_key);
                (VerifyKey::from(&sign_key), sign_key)
            },
             KeyType::X25519KeyAgreementKey2019 => {
                let secret = EphemeralSecret::from(priv_key);
                (PublicKey::from(&secret), secret)
             },
             _ => return Err(Error::UnsupportedKeyType),
        };

        Ok(KeyPair {
            public_key: PublicKeyInfo {
                controller: vec![],
                key_type: key_type,
                public_key: pk,
            },
            private_key: sk,
        })
    }

    pub fn random_pair(key_type: KeyType) -> Result<KeyPair, Error> {
        let (pk, sk) = match key_type {
            KeyType::X25519KeyAgreementKey2019 => {
                let secret = EphemeralSecret::new(OsRng);
                (PublicKey::from(&secret), secret)
            },
            KeyType::Ed25519VerificationKey2018 => {
                Keypair::generate(OsRng)
            },
            KeyType::EcdsaSecp256k1VerificationKey2019
            | KeyType::EcdsaSecp256k1RecoveryMethod2020 => {
                let sign_key = SigningKey::random(&mut OsRng);
                (VerifyKey::from(&sign_key), sign_key)
            },
            _ => return Err(Error::UnsupportedKeyType),
        };

        Ok(KeyPair {
            public_key: PublicKeyInfo {
                controller: vec![],
                key_type: key_type,
                public_key: pk,
            },
            private_key: sk,
        })
    }
    pub fn controller(self, controller: Vec<String>) -> Self {
        KeyPair {
            public_key: self.public_key.controller(controller),
            ..self
        }
    }
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        match self.public_key.key_type {
            KeyType::Ed25519VerificationKey2018 => {
                Ok(x25519(data, &self.private_key))
             },
            KeyType::EcdsaSecp256k1VerificationKey2019 => {
                let sign_key = SigningKey::from(&self.private_key);
                Ok(sign_key.sign(data))
            },
            KeyType::EcdsaSecp256k1RecoveryMethod2020 => {
                let sign_key = SigningKey::from(&self.private_key.0);
                // WARN: Signature type must be annotated to be recoverable!
                let signature: recoverable::Signature = sign_key.sign(data);
                Ok(signature)
            },
            _ => Err(Error::WrongKeyType),
        }
    }
    pub fn decrypt(&self, data: &[u8], _aad: &[u8]) -> Result<Vec<u8>, Error> {
        match self.public_key.key_type {
            // default use xChaCha20Poly1905 with x25519 key agreement
            KeyType::X25519KeyAgreementKey2019 => unseal_box::<X25519_BASEPOINT_BYTES, ChaCha20Poly1305>(
                data,
                &self.public_key.public_key,
                &self.private_key,
            ),
            _ => Err(Error::WrongKeyType),
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
fn key_pair_new_ed25519() {
    // Test vector from https://fossies.org/linux/tor/src/test/ed25519_vectors.inc
    let test_sk =
        hex::decode("26c76712d89d906e6672dafa614c42e5cb1caac8c6568e4d2493087db51f0d36").unwrap();
    let expected_pk =
        hex::decode("c2247870536a192d142d056abefca68d6193158e7c1a59c1654c954eccaff894").unwrap();

    let key_entry = KeyPair::new(KeyType::Ed25519VerificationKey2018, &test_sk).unwrap();

    assert!(key_entry.public_key.key_type == KeyType::Ed25519VerificationKey2018);
    assert_eq!(key_entry.public_key.controller, Vec::<String>::new());
    assert_eq!(key_entry.public_key.public_key.0, expected_pk);
    assert_eq!(
        key_entry.private_key.0,
        [&test_sk[..], &expected_pk[..]].concat()
    )
}

#[test]
fn keccak256_correct_output() {
    let input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let mut hasher = Keccak256::new();
    hasher.update(input.as_bytes());
    let output = hasher.finalize();
    assert_eq!(hex::encode(output), "45d3b367a6904e6e8d502ee04999a7c27647f91fa845d456525fd352ae3d7371");
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
    assert_eq!(key_entry.private_key.0, test_sk);
    assert_eq!(key_entry.public_key.public_key.0, expected_pk);
}

#[test] // TODO Finalize
fn key_pair_new_ecdsa_x25519() -> Result<(), Error> {
    // Self generated test vector.
    let test_sk = hex::decode("1c1179a560d092b90458fe6ab8291215a427fcd6b3927cb240701778ef55201927c96646f2d4632d4fc241f84cbc427fbc3ecaa95becba55088d6c7b81fc5bbf").unwrap();
    let expected_pk =
        hex::decode("27c96646f2d4632d4fc241f84cbc427fbc3ecaa95becba55088d6c7b81fc5bbf").unwrap();

    let key_entry = KeyPair::new(KeyType::X25519KeyAgreementKey2019, &test_sk)?;

    assert!(key_entry.public_key.key_type == KeyType::X25519KeyAgreementKey2019);
    assert_eq!(key_entry.public_key.controller, Vec::<String>::new());
    assert_eq!(key_entry.private_key.0, test_sk);
    assert_eq!(key_entry.public_key.public_key.0, expected_pk);
    Ok(())
}
