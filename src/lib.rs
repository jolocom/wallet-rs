#[macro_use]
extern crate arrayref;
extern crate aead;
extern crate ed25519_dalek;
extern crate chacha20poly1305;
extern crate thiserror;
extern crate wasm_bindgen;

use wasm_bindgen::prelude::*;

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

/// Wrapper enum for proper error handling
#[wasm_bindgen]
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
    /// Non-paque errors wrapper for aead crate
    #[error("cryptography failure in aead")]
    AeadCryptoError,
    #[error("cryptography failure in ecdsa")]
    EcdsaCryptoError,
    #[error("cryptography failure in ed25519")]
    EdCryptoError,
    /// Opaque errors wrapper for secp256k1 crate
    /// #Transparent errors cannot be used with WASM
    ///
    /// Serde crate errors
    #[error("Serde json serialization failure")]
    Serde,
    /// utf8 conversion errors
    #[error("Utf8 conversion error")]
    Utf8,
    /// Other errors implementing `std::error::Error`
    #[error("Generic failure")]
    Other
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
