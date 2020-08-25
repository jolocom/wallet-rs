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
        public_key_info::{to_recoverable_signature, KeyType, PublicKeyInfo},
        Content, ContentEntity,
    };
    pub use crate::locked::LockedWallet;
    pub use crate::unlocked::UnlockedWallet;
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use serde_json;

    #[test]
    fn secp256k1_recoverable_round_trip() -> Result<(), String> {
        let message = "hello".as_bytes();
        let mut w = UnlockedWallet::new("thing");
        let pk_info = w.new_key(KeyType::EcdsaSecp256k1RecoveryMethod2020, None)?;

        let sig = w.sign_raw(&pk_info.id, &message)?;

        assert_eq!(
            Ok(true),
            match pk_info.content {
                Content::KeyPair(r_pk_inf) => r_pk_inf.public_key.verify(&message, &sig),
                _ => Ok(false),
            }
        );
        Ok(())
    }

    #[test]
    fn wallet() -> Result<(), String> {
        let mut w = UnlockedWallet::new("thing");
        w.new_key(KeyType::EcdsaSecp256k1RecoveryMethod2020, None)?;
        w.new_key(KeyType::EcdsaSecp256k1RecoveryMethod2020, None)?;
        w.new_key(KeyType::EcdsaSecp256k1RecoveryMethod2020, None)?;
        w.new_key(KeyType::EcdsaSecp256k1RecoveryMethod2020, None)?;
        w.new_key(KeyType::EcdsaSecp256k1RecoveryMethod2020, None)?;
        let pass = "My Password".to_string();

        let lw = w.lock(pass.as_bytes())?;

        let uw = lw.unlock(pass.as_bytes())?;

        assert_eq!(5, uw.get_keys().len());

        Ok(())
    }
}
