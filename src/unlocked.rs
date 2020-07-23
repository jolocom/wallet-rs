use crate::{
    contents::{
        key::{Key, KeyType},
        Content, ContentEntity,
    },
    locked::LockedWallet,
};
use serde::{Deserialize, Serialize};
use serde_json::to_string;
use std::collections::HashMap;
use ursa::{
    encryption::symm::prelude::*,
    hash::{sha3::Sha3_256, Digest},
};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct UnlockedWallet {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    pub wallet_type: Vec<String>,
    contents: HashMap<String, ContentEntity>,
}

impl UnlockedWallet {
    pub fn new(id: &str) -> Self {
        UnlockedWallet {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".to_string(),
                "https://transmute-industries.github.io/universal-wallet/contexts/wallet-v1.json"
                    .to_string(),
            ],
            id: id.to_string(),
            wallet_type: vec!["UniversalWallet2020".to_string()],
            contents: HashMap::new(),
        }
    }

    pub fn new_key(&mut self, key_type: KeyType) -> Result<String, String> {
        let id = Uuid::new_v4().to_urn().to_string();
        self.contents.insert(
            id.clone(),
            ContentEntity {
                context: vec!["https://transmute-industries.github.io/universal-wallet/contexts/wallet-v1.json".to_string()],
                id: id.clone(),
                content: Content::Key(
                    Key::random_pair(key_type)?.controller(vec![self.id.clone()]),
                ),
            },
        );
        Ok(id)
    }
    pub fn get_keys(&self) -> Vec<ContentEntity> {
        self.contents
            .iter()
            .filter_map(|(_, content)| match &content.content {
                Content::Key(k) => Some(ContentEntity {
                    context: content.context.clone(),
                    id: content.id.clone(),
                    content: Content::Key(k.clean()),
                }),
                _ => None,
            })
            .collect()
    }

    pub fn sign_raw(&self, data: &[u8], key_ref: &str) -> Result<Vec<u8>, String> {
        match self.contents.get(key_ref) {
            Some(c) => match &c.content {
                Content::Key(k) => k.sign(data),
                _ => Err("incorrect content type".to_string()),
            },
            None => Err("no key found".to_string()),
        }
    }
    pub fn verify_raw(&self, data: &[u8], key_ref: &str, signature: &[u8]) -> Result<bool, String> {
        match self.contents.get(key_ref) {
            Some(c) => match &c.content {
                Content::Key(k) => k.verify(data, signature),
                _ => Err("incorrect content type".to_string()),
            },
            None => Err("no key found".to_string()),
        }
    }
    pub fn decrypt(&self, data: &[u8], key_ref: &str) -> Result<Vec<u8>, String> {
        match self.contents.get(key_ref) {
            Some(c) => match &c.content {
                Content::Key(k) => k.decrypt(data),
                _ => Err("incorrect content type".to_string()),
            },
            None => Err("no key found".to_string()),
        }
    }
    pub fn lock(&self, key: &[u8]) -> Result<LockedWallet, String> {
        let mut sha3 = Sha3_256::new();
        sha3.input(key);
        let pass = sha3.result();

        let aes = SymmetricEncryptor::<Aes256Gcm>::new_with_key(pass).map_err(|e| e.to_string())?;

        Ok(LockedWallet {
            id: self.id.clone(),
            ciphertext: aes
                .encrypt_easy(
                    self.id.as_bytes(),
                    &to_string(&self).map_err(|e| e.to_string())?.as_bytes(),
                )
                .map_err(|e| e.to_string())?,
        })
    }
}
