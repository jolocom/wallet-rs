use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Key {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    pub controller: Vec<String>,
    #[serde(rename = "type")]
    pub key_type: KeyType,
    #[serde(flatten)]
    pub public_key: PublicKeyEncoding,
    #[serde(flatten)]
    private_key: Option<PrivateKeyEncoding>,
}

impl Key {
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, 'str> {
        todo!()
    }
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), 'str> {
        todo!()
    }
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, 'str> {
        todo!()
    }
}

#[derive(Serialize, Deserialize)]
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
    Unknown,
    PublicKeyPem(String),
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
