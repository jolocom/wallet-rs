pub mod encryption;
pub mod entropy;
pub mod key_pair;
pub mod public_key_info;

use serde::{ser::SerializeSeq, Deserialize, Deserializer, Serialize, Serializer};

use public_key_info::PublicKeyInfo;
use std::collections::hash_map::*;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ContentEntity {
    #[serde(rename = "@context", default)]
    pub context: Vec<String>,
    pub id: String,

    #[serde(flatten)]
    pub content: Content,
}

impl ContentEntity {
    /// Cleans the entity of any sensative material
    pub fn clean(self) -> Self {
        match self.content {
            Content::KeyPair(kp) => Content::PublicKey(kp.get_public_key()).to_entity(&self.id),
            _ => self,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum Content {
    Entropy(entropy::Entropy),
    KeyPair(key_pair::KeyPair),
    PublicKey(public_key_info::PublicKeyInfo),
}

impl Content {
    pub fn to_entity(&self, id: &str) -> ContentEntity {
        content_to_entity(self, id)
    }
}

fn content_to_entity(content: &Content, id: &str) -> ContentEntity {
    ContentEntity {
        context: vec![
            "https://transmute-industries.github.io/universal-wallet/contexts/wallet-v1.json"
                .to_string(),
        ],
        id: id.to_owned(),
        content: content.clone(),
    }
}

#[derive(Clone)]
pub struct Contents(HashMap<String, Content>);

impl Contents {
    pub fn new() -> Self {
        Self(HashMap::<String, Content>::new())
    }

    pub fn insert(&mut self, id: &str, content: Content) -> Option<&Content> {
        self.0.insert(id.to_owned(), content);
        self.get(id)
    }

    pub fn import(&mut self, content: Content) -> Option<(String, &Content)> {
        let id = Uuid::new_v4().to_urn().to_string();
        Some((id.clone(), self.insert(&id, content)?))
    }

    pub fn get(&self, id: &str) -> Option<&Content> {
        self.0.get(id)
    }

    pub fn get_by_controller(&self, controller: &str) -> Option<(String, &Content)> {
        self.0.iter().find_map(|(id, content)| match content {
            Content::KeyPair(kp) if kp.public_key.controller.iter().any(|c| c == controller) => {
                Some((id.to_string(), content))
            }
            Content::PublicKey(pk) if pk.controller.iter().any(|c| c == controller) => {
                Some((id.to_string(), content))
            }
            _ => None,
        })
    }

    pub fn set_key_controller(&mut self, key_ref: &str, controller: &str) -> Option<&Content> {
        let oldk = self.0.remove(key_ref)?;
        self.insert(
            key_ref,
            match oldk {
                Content::PublicKey(pk) => Content::PublicKey(PublicKeyInfo {
                    controller: vec![controller.to_string()],
                    ..pk.clone()
                }),
                Content::KeyPair(kp) => {
                    Content::KeyPair(kp.set_controller(vec![controller.to_owned()]))
                }
                _ => oldk,
            },
        );
        self.0.get(key_ref)
    }

    pub fn get_keys(&self) -> Vec<(String, &Content)> {
        self.0
            .iter()
            .filter_map(|(id, content)| match content {
                Content::Entropy(_) => None,
                _ => Some((id.to_string(), content)),
            })
            .collect()
    }
}

impl Serialize for Contents {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for (id, content) in &self.0 {
            seq.serialize_element(&content_to_entity(&content, &id))?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for Contents {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self(
            Vec::<ContentEntity>::deserialize(deserializer)?
                .into_iter()
                .map(|ce| (ce.id, ce.content))
                .collect(),
        ))
    }
}
