pub mod encryption;
pub mod entropy;
pub mod key_pair;
pub mod public_key_info;

use serde::{ser::SerializeSeq, Deserialize, Deserializer, Serialize, Serializer};

use key_pair::KeyPair;
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

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
pub enum Content {
    Entropy(entropy::Entropy),
    KeyPair(key_pair::KeyPair),
    PublicKey(public_key_info::PublicKeyInfo),
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

    pub fn insert(&mut self, id: &str, content: Content) -> Option<ContentEntity> {
        self.0.insert(id.to_owned(), content);
        self.get(id)
    }

    pub fn import(&mut self, content: Content) -> Option<ContentEntity> {
        self.insert(&Uuid::new_v4().to_urn().to_string(), content)
    }

    pub fn get(&self, id: &str) -> Option<ContentEntity> {
        self.0.get(id).and_then(|c| Some(content_to_entity(c, id)))
    }

    pub fn get_key(&self, key_ref: &str) -> Option<ContentEntity> {
        let c = self.0.get(key_ref)?;
        Some(content_to_entity(
            &match &c {
                Content::KeyPair(kp) => Content::PublicKey(kp.clean()),
                Content::PublicKey(pk) => Content::PublicKey(pk.clone()),
                _ => return None,
            },
            key_ref,
        ))
    }

    pub fn get_by_controller(&self, controller: &str) -> Option<ContentEntity> {
        self.0.iter().find_map(|(id, content)| {
            Some(content_to_entity(
                &Content::PublicKey(match content {
                    Content::KeyPair(kp)
                        if kp.public_key.controller.iter().any(|c| c == controller) =>
                    {
                        kp.clean()
                    }
                    Content::PublicKey(pk) if pk.controller.iter().any(|c| c == controller) => {
                        pk.clone()
                    }
                    _ => return None,
                }),
                id,
            ))
        })
    }

    pub fn set_key_controller(&mut self, key_ref: &str, controller: &str) -> Option<ContentEntity> {
        let oldk = self.get(key_ref)?;
        self.insert(
            key_ref,
            match oldk.content {
                Content::PublicKey(pk) => Content::PublicKey(PublicKeyInfo {
                    controller: vec![controller.to_string()],
                    ..pk
                }),
                Content::KeyPair(kp) => Content::KeyPair(KeyPair {
                    public_key: PublicKeyInfo {
                        controller: vec![controller.to_string()],
                        ..kp.public_key
                    },
                    ..kp
                }),
                _ => oldk.content,
            },
        );
        self.get_key(key_ref)
    }

    pub fn get_pub_keys(&self) -> Vec<ContentEntity> {
        self.0
            .iter()
            .filter_map(|(id, content)| {
                Some(content_to_entity(
                    &Content::PublicKey(match &content {
                        Content::KeyPair(kp) => kp.clean(),
                        Content::PublicKey(pk) => pk.clone(),
                        _ => return None,
                    }),
                    id,
                ))
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
