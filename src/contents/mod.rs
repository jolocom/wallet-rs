pub mod encryption;
pub mod entropy;
pub mod key_pair;
pub mod public_key_info;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct ContentEntity {
    #[serde(rename = "@context", default)]
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
    PublicKey(public_key_info::PublicKeyInfo),
}
