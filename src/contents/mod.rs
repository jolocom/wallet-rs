pub mod entropy;
pub mod key;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ContentEntity {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,

    #[serde(flatten)]
    pub content: Content,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum Content {
    Entropy(entropy::Entropy),
    Key(key::Key),
}
