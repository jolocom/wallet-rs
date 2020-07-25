pub mod contents;
pub mod locked;
pub mod unlocked;

use ursa::encryption::random_vec;

pub fn get_random(len: usize) -> Result<Vec<u8>, String> {
    random_vec(len).map_err(|e| e.to_string())
}

pub mod prelude {
    pub use crate::contents::{
        key_pair::KeyPair,
        public_key_info::{KeyType, PublicKeyInfo},
        Content,
    };
    pub use crate::locked::LockedWallet;
    pub use crate::unlocked::UnlockedWallet;
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    #[test]
    fn it_works() -> Result<(), String> {
        let mut w = UnlockedWallet::new("thing");
        let pk_info = w.new_key(KeyType::Ed25519VerificationKey2018, None)?;
        let message = "hi there";
        let sig = w.sign_raw(message.as_bytes(), &pk_info.id)?;

        print!(
            "\n{}\n",
            serde_json::to_string(&pk_info).map_err(|e| e.to_string())?
        );

        assert_eq!(
            Ok(true),
            match pk_info.content {
                Content::PublicKey(pk) => pk.verify(message.as_bytes(), &sig),
                _ => Ok(false),
            }
        );

        let lw = w.lock(message.as_bytes())?;

        let uw = lw.unlock(message.as_bytes())?;

        // let sig2 = uw.sign_raw(message.as_bytes(), &kref)?;

        // assert_eq!(Ok(true), w.verify_raw(message.as_bytes(), &kref, &sig));
        // assert_eq!(Ok(true), uw.verify_raw(message.as_bytes(), &kref, &sig2));

        Ok(())
    }
}
