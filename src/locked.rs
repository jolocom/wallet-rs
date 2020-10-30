use super::unlocked::UnlockedWallet;
use super::Error;
use serde::{Deserialize, Serialize};
use serde_json::from_str;
use sha3::{
    Digest,
    Sha3_256
};
use chacha20poly1305::{
    XNonce,
    XChaCha20Poly1305,
    aead::{
        Aead,
        NewAead
    },
};
use wasm_bindgen::prelude::*;

/// Represents wallet in locked (encrypted) state
#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct LockedWallet {
    /// Wallet ID
    pub id: String,
    /// Encrypted wallet Content
    pub ciphertext: Vec<u8>,
}

#[wasm_bindgen]
impl LockedWallet {
    /// Instantiates encrypted wallet from ID and ciphertext
    ///
    /// # Parameters
    ///
    /// * id - `&str` of wallet's ID
    /// * ct - encrypted content of the wallet
    ///
    pub fn new(id: &str, ct: Vec<u8>) -> Self {
        Self {
            id: id.to_string(),
            ciphertext: ct,
        }
    }

    /// Unlocks the wallet into `UnlockedWallet`
    ///
    /// # Parameters
    ///
    /// * key - password to decrypt content with
    ///
    pub fn unlock(&self, key: &[u8]) -> Result<UnlockedWallet, Error> {
        let mut sha3 = Sha3_256::new();
        sha3.update(key);
        let pass = sha3.finalize();

        let cha_cha = XChaCha20Poly1305::new(&pass);

        let nonce_start = self.ciphertext.len() - 24;
        let nonce = XNonce::from_slice(&self.ciphertext[nonce_start..]);
        let content = &self.ciphertext[..nonce_start];
        let dec = cha_cha
            .decrypt(&nonce, content)
            .map_err(|e| Error::AeadCryptoError(e))?;

        let as_str = std::str::from_utf8(&dec)
            .map_err(|e| Error::Utf8(e))?;

        from_str(as_str)
            .map_err(|e| Error::Serde(e))
    }
}
