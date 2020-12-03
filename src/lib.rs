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

pub mod prelude {
    pub use crate::contents::{
        key_pair::KeyPair,
        public_key_info::{to_recoverable_signature, KeyType, PublicKeyInfo},
        Content, ContentEntity,
    };
    pub use crate::locked::LockedWallet;
    pub use crate::unlocked::UnlockedWallet;
}

/// Helpful for generating bytes using the operating system random number generator
pub fn get_random(bytes: usize) -> Result<Vec<u8>, Error> {
    let mut value = vec![0u8; bytes];
    OsRng.fill_bytes(value.as_mut_slice());
    Ok(value)
}

/// Wrapper enum for proper error handling
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Indicates error during key insertion
    #[error("error inserting key")]
    KeyInsertionError,
    /// Type of used key is not supported in this context
    #[error("key type unsupported")]
    UnsupportedKeyType,
    /// Type of used key is invalid in this context
    #[error("key type wrong")]
    WrongKeyType,
    #[error("key size incorrect")]
    WrongKeyLength,
    /// No key found
    #[error("key not found")]
    KeyNotFound,
    /// Content type is incorrect in current context
    #[error("incorrect content type")]
    ContentTypeIncorrect,
    /// Internal encryption errors
    #[error("Box is to small")]
    BoxToSmall,
    #[error("failed to add Key Pair")]
    KeyPairAddFailed,
    /// External encryption errors
    ///
    /// Opaque errors wrapper for aead crate
    #[error("cryptography failure in aead: {0}")]
    AeadCryptoError(aead::Error),
    #[error("cryptography failure in ecdsa: {0}")]
    EcdsaCryptoError(k256::ecdsa::Error),
    #[error("cryptography failure in ed25519: {0}")]
    EdCryptoError(ed25519_dalek::ed25519::Error),
    /// Opaque errors wrapper for secp256k1 crate
    /// #Transparent errors
    ///
    /// Serde crate errors
    #[error(transparent)]
    Serde(#[from] serde_json::error::Error),
    /// utf8 conversion errors
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),
    /// Other errors implementing `std::error::Error`
    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error>)
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use super::Error;

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
