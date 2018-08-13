use error::Error;

/// `Result` type for CBOR serialisation and deserialisation.
pub type Result<T> = super::internal::core::result::Result<T, Error>;
