use rand_core::{OsRng, RngCore};

#[macro_use]
extern crate arrayref;
extern crate aead;
extern crate ed25519_dalek;
extern crate chacha20poly1305;
extern crate thiserror;

pub mod contents;
pub mod locked;
pub mod unlocked;
mod error;

pub mod prelude {
    pub use crate::contents::{
        key_pair::KeyPair,
        public_key_info::{to_recoverable_signature, KeyType, PublicKeyInfo},
        Content, ContentEntity,
    };
    pub use crate::locked::LockedWallet;
    pub use crate::unlocked::UnlockedWallet;
}
#[cfg(feature = "didcomm")]
pub use didcomm_rs;

pub use error::Error as Error;

/// Helpful for generating bytes using the operating system random number generator
pub fn get_random(bytes: usize) -> Result<Vec<u8>, Error> {
    let mut value = vec![0u8; bytes];
    OsRng.fill_bytes(value.as_mut_slice());
    Ok(value)
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use super::error::Error;

    #[test]
    fn secp256k1_recoverable_round_trip() -> Result<(), Error> {
        let message = "hello".as_bytes();
        let mut w = UnlockedWallet::new("thing is very beautiful!");
        let pk_info = w.new_key(KeyType::EcdsaSecp256k1RecoveryMethod2020, None)?;

        let sig = w.sign_raw(&pk_info.id, &message)?;

        assert!(
            match pk_info.content {
                Content::PublicKey(r_pk_inf) => r_pk_inf.verify(&message, &sig)?,
                _ => false,
            }
        );
        Ok(())
    }

    #[test]
    fn wallet() -> Result<(), Error> {
        let mut w = UnlockedWallet::new("thing is very beautiful!");
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
