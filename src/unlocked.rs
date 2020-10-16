use crate::{
    contents::{key_pair::KeyPair, public_key_info::KeyType, Content, ContentEntity, Contents},
    locked::LockedWallet,
    Error,
};
use generic_array::GenericArray;
use serde::{Deserialize, Serialize};
use serde_json::to_string;
use sha3::{
    Digest,
    Sha3_256
};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{
        Aead,
        NewAead,
    },
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
    ) -> Result<ContentEntity, Error> {
        let kp = KeyPair::random_pair(key_type)
            .map_err(|e| Error::Other(Box::new(e)))?;
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
            .map(|(id, content)| content.to_entity(&id).clean())
            .ok_or(Error::KeyPairAddFailed)
    }

    pub fn import_content(&mut self, content: &Content) -> Option<ContentEntity> {
        self.contents
            .import(content.clone())
            .map(|(id, content)| content.to_entity(&id).clean())
    }

    pub fn set_content(&mut self, cref: &str, content: Content) -> Option<ContentEntity> {
        self.contents
            .insert(cref, content)
            .map(|content| content.to_entity(cref).clean())
    }

    pub fn get_key(&self, key_ref: &str) -> Option<ContentEntity> {
        self.contents
            .get(key_ref)
            .and_then(|content| match content {
                Content::Entropy(_) => None,
                _ => Some(content.to_entity(key_ref).clean()),
            })
    }

    pub fn get_key_by_controller(&self, controller: &str) -> Option<ContentEntity> {
        self.contents
            .get_by_controller(controller)
            .map(|(id, content)| content.to_entity(&id).clean())
    }

    pub fn set_key_controller(&mut self, key_ref: &str, controller: &str) -> Option<()> {
        self.contents.set_key_controller(key_ref, controller)?;
        Some(())
    }

    pub fn get_keys(&self) -> Vec<ContentEntity> {
        self.contents
            .get_keys()
            .iter()
            .map(|(id, content)| content.to_entity(id).clean())
            .collect()
    }

    pub fn sign_raw(&self, key_ref: &str, data: &[u8]) -> Result<Vec<u8>, Error> {
        match self.contents.get(key_ref) {
            Some(c) => match &c {
                Content::KeyPair(k) => k.sign(data),
                _ => Err(Error::ContentTypeIncorrect),
            },
            None => Err(Error::KeyNotFound),
        }
    }

    pub fn decrypt(&self, key_ref: &str, data: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        match self.contents.get(key_ref) {
            Some(c) => match &c {
                Content::KeyPair(k) => k.decrypt(data, aad),
                _ => Err(Error::ContentTypeIncorrect),
            },
            None => Err(Error::KeyNotFound),
        }
    }

    pub fn lock(&self, key: &[u8]) -> Result<LockedWallet, Error> {
        let mut sha3 = Sha3_256::new();
        sha3.update(key);
        let pass = sha3.finalize();

        let cha_cha = ChaCha20Poly1305::new(GenericArray::from_slice(key));

        Ok(LockedWallet {
            id: self.id.clone(),
            ciphertext: cha_cha
                .encrypt(
                    GenericArray::from_slice(self.id.as_bytes()),
                    to_string(&self).map_err(|e| Error::Serde(e))?.as_bytes(),
                )
                .map_err(|e| Error::AeadCryptoError(e))?,
        })
    }

}
