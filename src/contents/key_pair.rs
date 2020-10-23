use super::encryption::unseal_box;
use super::public_key_info::{KeyType, PublicKeyInfo};
use k256::{
    ecdsa::{
        SigningKey,
        VerifyKey,
        Signature,
        signature::Signer,
        recoverable,
    },
};
use serde::{Deserialize, Serialize};
use x25519_dalek::{
    x25519,
    PublicKey,
    StaticSecret,
};
use crypto_box::SecretKey;
use ed25519_dalek::{
    self,
    Keypair,
};
use rand_core::OsRng;
use crate::Error;

/// Serializable struct to hold pair of public and private keys.
/// Universal for any key types as keys stored as bytes.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyPair {
    /// Public key is instance of `PublicKeyInfo` struct.
    #[serde(flatten)]
    pub public_key: PublicKeyInfo,
    /// Private key in form of vector of bytes.
    // TODO: should this prop really be pub???
    pub private_key: Vec<u8>,
}

impl KeyPair {
    /// Constructs set of keys from private key.
    /// Public key generated in the method from private key provided.
    ///
    /// # Arguments
    ///
    /// *`key_type` - variont of `KeyType` enum.
    /// Currently supportet key types are:
    /// `Ed25519VerificationKey2018` [W3C](https://w3c-ccg.github.io/ld-cryptosuite-registry/#ed25519)<br>
    /// `EcdsaSecp256k1VerificationKey2019` [W3C](https://w3c-ccg.github.io/ld-cryptosuite-registry/#ecdsasecp256k1signature2019)<br>
    /// `EcdsaSecp256k1RecoveryMethod2020` [W3C](https://w3c-ccg.github.io/ld-cryptosuite-registry/#ecdsasecp256k1recoverysignature2020)<br>
    //  TODO: find proper link for x25519 key
    /// `X25519KeyAgreementKey2019` [W3C](https://www.w3.org/TR/did-core/#key-types-and-formats)<br>
    ///
    pub fn new(key_type: KeyType, priv_key: &Vec<u8>) -> Result<Self, Error> {
        let (pk, sk) = match key_type {
            KeyType::Ed25519VerificationKey2018 => {
                let sk = ed25519_dalek::SecretKey::from_bytes(priv_key)
                    .map_err(|e| Error::EdCryptoError(e))?;
                let pk: ed25519_dalek::PublicKey = (&sk).into();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            },
            KeyType::EcdsaSecp256k1VerificationKey2019
            | KeyType::EcdsaSecp256k1RecoveryMethod2020 => {
                let sign_key = SigningKey::new(priv_key)
                    .map_err(|e| Error::EcdsaCryptoError(e))?;
                let verify_key = VerifyKey::from(&sign_key);
                (verify_key.to_bytes().to_vec(), 
                sign_key.to_bytes().iter_mut().map(|v| *v).collect::<Vec<u8>>())
            },
             KeyType::X25519KeyAgreementKey2019 => {
                let secret = StaticSecret::from(array_ref!(priv_key, 0, 32).to_owned());
                let pk = *PublicKey::from(&secret).as_bytes();
                (pk.to_vec(),
                secret.to_bytes().to_vec())
             },
             _ => return Err(Error::UnsupportedKeyType),
        };

        Ok(KeyPair{
            public_key: PublicKeyInfo {
                controller: vec![],
                key_type,
                public_key: pk,
            },
            private_key: sk,
        })
    }

    /// Generates random `KeyPair` of specified `KeyType` type.
    ///
    /// *`key_type` - variont of `KeyType` enum.
    ///
    /// # Examples
    ///
    /// ```
    /// # use crate::{
    /// #    universal_wallet::{
    /// #       Error,
    /// #       contents::{
    /// #           public_key_info::KeyType,
    /// #           key_pair::KeyPair,
    /// #       },
    /// #    },
    /// # };
    /// # fn rkp() -> Result<(), Error> {
    ///     let key_pair = KeyPair::random_pair(KeyType::EcdsaSecp256k1VerificationKey2019)?;
    /// #   Ok(())
    /// # }
    /// ```
    ///
    pub fn random_pair(key_type: KeyType) -> Result<KeyPair, Error> {
        let (pk, sk) = match key_type {
            KeyType::X25519KeyAgreementKey2019 => {
                let sk = StaticSecret::new(OsRng);
                (PublicKey::from(&sk).as_bytes().to_vec(), sk.to_bytes().to_vec())
            },
            KeyType::Ed25519VerificationKey2018 => {
                let kp = Keypair::generate(&mut OsRng);
                (kp.public.as_bytes().to_vec(), kp.secret.as_bytes().to_vec())
            },
            KeyType::EcdsaSecp256k1VerificationKey2019
            | KeyType::EcdsaSecp256k1RecoveryMethod2020 => {
                let sign_key = SigningKey::random(&mut OsRng);
                (VerifyKey::from(&sign_key).to_bytes().to_vec(), sign_key.to_bytes().to_vec())
            },
            _ => return Err(Error::UnsupportedKeyType),
        };

        Ok(KeyPair {
            public_key: PublicKeyInfo {
                controller: vec![],
                key_type,
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
                Ok(x25519(array_ref!(data, 0, 32).to_owned(), array_ref!(&self.private_key, 0, 32).to_owned()).to_vec())
             },
            KeyType::EcdsaSecp256k1VerificationKey2019 => {
                let sign_key = SigningKey::new(&self.private_key)
                    .map_err(|e| Error::EcdsaCryptoError(e))?;
                let signature: Signature = sign_key.sign(data);
                Ok(signature.as_ref().to_vec())
            },
            KeyType::EcdsaSecp256k1RecoveryMethod2020 => {
                let sign_key = SigningKey::new(&self.private_key[..])
                    .map_err(|e| Error::EcdsaCryptoError(e))?;
                // WARN: Signature type must be annotated to be recoverable!
                let signature: recoverable::Signature = sign_key.sign(data);
                Ok(signature.as_ref().to_vec())
            },
            _ => Err(Error::WrongKeyType),
        }
    }
    pub fn decrypt(&self, data: &[u8], _aad: &[u8]) -> Result<Vec<u8>, Error> {
        match self.public_key.key_type {
            // default use xChaCha20Poly1905 with x25519 key agreement
            KeyType::X25519KeyAgreementKey2019 => unseal_box(
                data,
                &SecretKey::from(array_ref!(&self.private_key, 0, 32).to_owned()),
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
    assert_eq!(key_entry.public_key.public_key, expected_pk);
    assert_eq!(
        [&key_entry.private_key[..], &key_entry.public_key.public_key[..]].concat(),
        [&test_sk[..], &expected_pk[..]].concat()
    )
}

#[test]
fn keccak256_correct_output() {
    use sha3::Keccak256;
    use blake2::Digest;
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
    assert_eq!(key_entry.private_key, test_sk);
    assert_eq!(key_entry.public_key.public_key, expected_pk);
}

#[test]
fn key_pair_new_ecdsa_x25519() -> Result<(), Error> {
    // Test vector from https://tools.ietf.org/html/rfc7748#section-6.1
    let test_sk =
        hex::decode("a8abababababababababababababababababababababababababababababab6b").unwrap();
    let expected_pk =
        hex::decode("e3712d851a0e5d79b831c5e34ab22b41a198171de209b8b8faca23a11c624859").unwrap();

    let key_entry = KeyPair::new(KeyType::X25519KeyAgreementKey2019, &test_sk)?;

    assert!(key_entry.public_key.key_type == KeyType::X25519KeyAgreementKey2019);
    assert_eq!(key_entry.public_key.controller, Vec::<String>::new());
    assert_eq!(key_entry.private_key, test_sk);
    assert_eq!(key_entry.public_key.public_key, expected_pk);
    Ok(())
}
