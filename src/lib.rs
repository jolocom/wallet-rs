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
        public_key_info::{KeyType, PublicKeyInfo, to_recoverable_signature},
        Content, ContentEntity,
    };
    pub use crate::locked::LockedWallet;
    pub use crate::unlocked::UnlockedWallet;
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;

    #[test]
    fn secp256k1_recoverable_round_trip() -> Result<(), String> {
        let message = "hello".as_bytes();
        let mut w = UnlockedWallet::new("thing");
        let pk_info = w.new_key(KeyType::EcdsaSecp256k1RecoveryMethod2020, None)?;   

        let sig = w.sign_raw(&pk_info.id, &message)?;

        assert_eq!(
            Ok(true),
            match pk_info.content {
                Content::PublicKey(r_pk_inf) => r_pk_inf.verify(&message, &sig),
                _ => Ok(false),
            }
        );
        Ok(())
    }
}
