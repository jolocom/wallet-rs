use super::unlocked::UnlockedWallet;
use super::Error;
use serde::{Deserialize, Serialize};
use serde_json::from_str;
use ursa::{
    encryption::symm::prelude::*,
    hash::{sha3::Sha3_256, Digest},
};

#[derive(Serialize, Deserialize)]
pub struct LockedWallet {
    pub id: String,
    pub ciphertext: Vec<u8>,
}

impl LockedWallet {
    pub fn new(id: &str, ct: Vec<u8>) -> Self {
        Self {
            id: id.to_string(),
            ciphertext: ct,
        }
    }

    pub fn unlock(&self, key: &[u8]) -> Result<UnlockedWallet, Error> {
        let mut sha3 = Sha3_256::new();
        sha3.input(key);
        let pass = sha3.result();

        let x_cha_cha = SymmetricEncryptor::<XChaCha20Poly1305>::new_with_key(pass)
            .map_err(|e| Error::AeadCryptoError(e))?;

        let dec = x_cha_cha
            .decrypt_easy(self.id.as_bytes(), &self.ciphertext)
            .map_err(|e| Error::AeadCryptoError(e))?;

        let as_str = std::str::from_utf8(&dec)
            .map_err(|e| Error::Utf8(e))?;

        from_str(as_str)
            .map_err(|e| Error::Serde(e))
    }
}
