use super::unlocked::UnlockedWallet;
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
    pub fn unlock(&self, key: &[u8]) -> Result<UnlockedWallet, String> {
        let mut sha3 = Sha3_256::new();
        sha3.input(key);
        let pass = sha3.result();

        let aes = SymmetricEncryptor::<Aes256Gcm>::new_with_key(pass).map_err(|e| e.to_string())?;

        let dec = aes
            .decrypt_easy(self.id.as_bytes(), &self.ciphertext)
            .map_err(|e| e.to_string())?;

        from_str(std::str::from_utf8(&dec).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
    }
}
