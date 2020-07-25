pub mod entropy;
pub mod key_pair;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct ContentEntity {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,

    #[serde(flatten)]
    pub content: Content,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Content {
    Entropy(entropy::Entropy),
    KeyPair(key_pair::KeyPair),
    PublicKey(key_pair::PublicKeyInfo),
}
