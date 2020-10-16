use super::unlocked::UnlockedWallet;
use super::Error;
use generic_array::GenericArray;
use serde::{Deserialize, Serialize};
use serde_json::from_str;
use sha3::{
    Digest,
    Sha3_256
};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{
        Aead,
        NewAead
    },
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
        sha3.update(key);
        let pass = sha3.finalize();

        let cha_cha = ChaCha20Poly1305::new(&GenericArray::from_slice(key));
        
        let dec = cha_cha
            .decrypt(GenericArray::from_slice(self.id.as_bytes()), self.ciphertext.as_slice())
            .map_err(|e| Error::AeadCryptoError(e))?;

        let as_str = std::str::from_utf8(&dec)
            .map_err(|e| Error::Utf8(e))?;

        from_str(as_str)
            .map_err(|e| Error::Serde(e))
    }
}
