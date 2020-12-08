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
    #[error(transparent)]
    EcdsaCryptoError(#[from] k256::ecdsa::Error),
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
    /// base64 decode errore transparent propagation
    #[error(transparent)]
    Base64DecodeError(#[from] base64::DecodeError),
    /// Other errors implementing `std::error::Error`
    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error>)
}
