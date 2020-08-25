use crate::{
    contents::{key_pair::KeyPair, public_key_info::KeyType, Content, ContentEntity, Contents},
    locked::LockedWallet,
};
use serde::{Deserialize, Serialize};
use serde_json::to_string;
use ursa::{
    encryption::symm::prelude::*,
    hash::{sha3::Sha3_256, Digest},
};

#[derive(Serialize, Deserialize)]
pub struct UnlockedWallet {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,

    #[serde(rename = "type")]
    pub wallet_type: Vec<String>,
    contents: Contents,
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
            contents: Contents::new(),
        }
    }

    // TODO provide a closure for transforming the key to a controller value
    pub fn new_key(
        &mut self,
        key_type: KeyType,
        key_controller: Option<Vec<String>>,
    ) -> Result<ContentEntity, String> {
        let kp = KeyPair::random_pair(key_type)?;
        let pk = kp.public_key.clone();
        let key_pair = Content::KeyPair(kp.controller(match key_controller {
            Some(c) => c,
            None => vec![[
                        self.id.clone(),
                        base64::encode_config(pk.public_key, base64::URL_SAFE),
                    ]
                    .join("#")
                    .to_string()],
        }));
        self.contents
            .import(key_pair)
            .ok_or("Failed to add Key Pair".to_string())
    }

    pub fn import_content(&mut self, content: &Content) -> Option<ContentEntity> {
        self.contents.import(content.clone())
    }

    pub fn set_content(&mut self, cref: &str, content: Content) -> Option<ContentEntity> {
        self.contents.insert(cref, content)
    }

    pub fn get_key(&self, key_ref: &str) -> Option<ContentEntity> {
        self.contents.get_key(key_ref)
    }

    pub fn get_key_by_controller(&self, controller: &str) -> Option<ContentEntity> {
        self.contents.get_by_controller(controller)
    }

    pub fn set_key_controller(&mut self, key_ref: &str, controller: &str) -> Option<()> {
        self.contents.set_key_controller(key_ref, controller)?;
        Some(())
    }

    pub fn get_keys(&self) -> Vec<ContentEntity> {
        self.contents.get_pub_keys()
    }

    pub fn sign_raw(&self, key_ref: &str, data: &[u8]) -> Result<Vec<u8>, String> {
        self.contents.sign_raw(key_ref, data)
    }

    pub fn decrypt(&self, key_ref: &str, data: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        self.contents.decrypt(key_ref, data, aad)
    }

    pub fn lock(&self, key: &[u8]) -> Result<LockedWallet, String> {
        let mut sha3 = Sha3_256::new();
        sha3.input(key);
        let pass = sha3.result();

        let xChaCha = SymmetricEncryptor::<XChaCha20Poly1305>::new_with_key(pass)
            .map_err(|e| e.to_string())?;

        Ok(LockedWallet {
            id: self.id.clone(),
            ciphertext: xChaCha
                .encrypt_easy(
                    self.id.as_bytes(),
                    &to_string(&self).map_err(|e| e.to_string())?.as_bytes(),
                )
                .map_err(|e| e.to_string())?,
        })
    }
}
