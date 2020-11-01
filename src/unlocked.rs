use crate::{
    contents::{key_pair::KeyPair, public_key_info::KeyType, Content, ContentEntity, Contents},
    locked::LockedWallet,
    Error,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::to_string;
use sha3::{
    Digest,
    Sha3_256
};
use chacha20poly1305::{
    XNonce,
    XChaCha20Poly1305,
    aead::{
        Aead,
        NewAead,
    },
};
use wasm_bindgen::prelude::*;

/// Represents unlocked wallet with it's content in raw form
#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct UnlockedWallet {
    /// JSON-LD `@context` key-value pair
    #[serde(rename = "@context")]
    pub context: Box<[JsValue]>,
    /// Wallet ID
    pub id: String,
    /// Type of the wallet. JSON property `type`
    #[serde(rename = "type")]
    pub wallet_type: Box<[JsValue]>,
    /// Wallet `Contents`
    contents: Contents,
}

#[wasm_bindgen]
impl UnlockedWallet {
    /// Constructs new instance with provided ID
    ///
    /// # Parameters
    ///
    /// * id - `&str` of ID to be used
    ///
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
    /// Generates new key pair of type specified and stores it in the wallet
    ///
    /// # Parameters
    ///
    /// * key_type - `KeyType` of desired new keypair to be generated
    /// * key_controller - Optional controller information
    ///
    // # Wasm parameters
    // Option<Box<[JsValue]> -> Option<Vec<String>>
    pub fn new_key(
        &mut self,
        key_type: KeyType,
        key_controller: Option<Box<[JsValue]>>,
    ) -> Result<ContentEntity, JsValue> {
        let kp = KeyPair::random_pair(key_type)
            .map_err(|e| Error::Other(Box::new(e)))?;
        let pk = kp.public_key.clone();
        let key_pair = Content::KeyPair(kp.set_controller(match key_controller {
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

    /// Imports provided content into wallet
    ///
    /// # Parameters
    ///
    /// * content - `Content` refference to be added to the wallet
    ///
    // # Wasm parameters
    // &JsValue => &Content
    pub fn import_content(&mut self, content: &JsValue) -> Option<ContentEntity> {
        self.contents
            .import(content.clone())
            .map(|(id, content)| content.to_entity(&id).clean())
    }

    // TODO: What exactly happening here?
    pub fn set_content(&mut self, cref: &str, content: Content) -> Option<ContentEntity> {
        self.contents
            .insert(cref, content)
            .map(|content| content.to_entity(cref).clean())
    }

    // TODO: What exactly happening here?
    pub fn get_key(&self, key_ref: &str) -> Option<ContentEntity> {
        self.contents
            .get(key_ref)
            .and_then(|content| match content {
                Content::Entropy(_) => None,
                _ => Some(content.to_entity(key_ref).clean()),
            })
    }

    /// Returns optional `ContentEntity` found by controller specified
    ///
    /// # Parameters
    ///
    /// * controller - search controller entry
    ///
    pub fn get_key_by_controller(&self, controller: &str) -> Option<ContentEntity> {
        self.contents
            .get_by_controller(controller)
            .map(|(id, content)| content.to_entity(&id).clean())
    }

    /// Sets controller information to the specific key
    ///
    /// # Parameters
    ///
    /// * key_ref - refference to the target key
    /// * controller - controller information to be attached
    ///
    pub fn set_key_controller(&mut self, key_ref: &str, controller: &str) -> Option<bool> {
        self.contents.set_key_controller(key_ref, controller)?;
        Some(true)
    }

    /// Returns `Vec` of `ContentEntity` from the wallet
    pub fn get_keys(&self) -> Vec<ContentEntity> {
        self.contents
            .get_keys()
            .iter()
            .map(|(id, content)| content.to_entity(id).clean())
            .collect()
    }

    /// Signs message with the key selected by refference
    ///
    /// # Properties
    ///
    /// * key_ref - key to be fetched and signed with
    /// * data - message to be signed by selected key
    ///
    pub fn sign_raw(&self, key_ref: &str, data: &[u8]) -> Result<Vec<u8>, JsValue> {
        match self.contents.get(key_ref) {
            Some(c) => match &c {
                Content::KeyPair(k) => k.sign(data),
                _ => Err(Error::ContentTypeIncorrect),
            },
            None => Err(Error::KeyNotFound),
        }
    }

    /// Decrypts provided cypher text using desired key by refference
    ///
    /// # Parameters
    ///
    /// * key_ref - key to be fetched to use for decription
    /// * data - cipher to be decrypted
    /// * aad - `Option` to be used for AAD algorithm
    ///
    // # Wasm parameters
    // Option<Box<&[JsValue]>> -> Option<&[u8]>
    pub fn decrypt(&self, key_ref: &str, data: &[u8], aad: Option<&Box<[JsValue]>) -> Result<Vec<u8>, JsValue> {
        match self.contents.get(key_ref) {
            Some(c) => match &c {
                Content::KeyPair(k) => k.decrypt(data, aad),
                _ => Err(Error::ContentTypeIncorrect),
            },
            None => Err(Error::KeyNotFound),
        }
    }

    /// Locks the wallet by encripting all the content and producing `LockedWallet`
    ///
    /// # Parameters
    ///
    /// * key - secret key (password) for the encription
    ///
    pub fn lock(&self, key: &[u8]) -> Result<LockedWallet, JsValue> {
        let mut sha3 = Sha3_256::new();
        sha3.update(key);
        let pass = sha3.finalize();

        let cha_cha = XChaCha20Poly1305::new(&pass);
        let mut nonce = get_nonce();//XNonce::from_slice(self.id.as_bytes());
        let mut cypher = cha_cha
        .encrypt(
            &nonce,
            to_string(&self).map_err(|e| Error::Serde(e))?.as_bytes(),
        )
        .map_err(|e| Error::AeadCryptoError(e))?;
        cypher.append(&mut nonce.iter_mut().map(|v| *v).collect());
        Ok(LockedWallet {
            id: self.id.clone(),
            ciphertext: cypher
        })
    }
}

// generates random `XNonce`
fn get_nonce() -> XNonce {
    let mut base = [0u8; 24];
    OsRng.fill_bytes(&mut base);
    *XNonce::from_slice(&base)
}
