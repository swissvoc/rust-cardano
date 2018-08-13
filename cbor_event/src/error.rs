use internal::core;

use types::Type;

/// all expected error for cbor parsing and serialising
#[derive(Debug)]
pub enum Error {
    ExpectedU8,
    ExpectedU16,
    ExpectedU32,
    ExpectedU64,
    ExpectedI8,
    ExpectedI16,
    ExpectedI32,
    ExpectedI64,
    ExpectedBool,
    ExpectedNull,
    ExpectedUndefined,
    ExpectedUnassigned,
    ExpectedFloat,
    ExpectedBreak,
    /// not enough data, the first element is the actual size, the second is
    /// the expected size.
    NotEnough(usize, usize),
    /// Were expecting a different [`Type`](../enum.Type.html). The first
    /// element is the expected type, the second is the current type.
    Expected(Type, Type),

    /// Were expecteing a supported Object Key
    UnsupportedKeyType(Type),
    /// this may happens when deserialising a [`RawCbor`](../de/struct.RawCbor.html);
    UnknownLenType(u8),
    IndefiniteLenNotSupported(Type),

    InvalidTextError(core::str::Utf8Error),
    WriteError(super::internal::WriteError),

    CustomError(&'static str),
}
impl From<core::str::Utf8Error> for Error {
    fn from(e: core::str::Utf8Error) -> Self { Error::InvalidTextError(e) }
}
impl From<super::internal::WriteError> for Error {
    fn from(e: super::internal::WriteError) -> Self { Error::WriteError(e) }
}

impl<'a> core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use Error::*;
        match self {
            ExpectedU8 => write!(f, "Invalid cbor: expected 8bit long unsigned integer"),
            ExpectedU16 => write!(f, "Invalid cbor: expected 16bit long unsigned integer"),
            ExpectedU32 => write!(f, "Invalid cbor: expected 32bit long unsigned integer"),
            ExpectedU64 => write!(f, "Invalid cbor: expected 64bit long unsigned integer"),
            ExpectedI8 => write!(f, "Invalid cbor: expected 8bit long negative integer"),
            ExpectedI16 => write!(f, "Invalid cbor: expected 16bit long negative integer"),
            ExpectedI32 => write!(f, "Invalid cbor: expected 32bit long negative integer"),
            ExpectedI64 => write!(f, "Invalid cbor: expected 64bit long negative integer"),
            ExpectedBool => write!(f, "Invalid cbor: expected special type value `Bool'"),
            ExpectedNull => write!(f, "Invalid cbor: expected special type value `Null'"),
            ExpectedUndefined => write!(f, "Invalid cbor: expected special type value `Undefined'"),
            ExpectedUnassigned => write!(f, "Invalid cbor: expected special type value `Unassigned'"),
            ExpectedFloat => write!(f, "Invalid cbor: expected expected special type value `Float'"),
            ExpectedBreak => write!(f, "Invalid cbor: expected expected special type value `Break'"),
            NotEnough(got, exp) => write!(f, "Invalid cbor: not enough bytes, expect {} bytes but received {} bytes.", exp, got),
            UnsupportedKeyType(t) => write!(f, "Invalid cbor: unsupported object key type `{:?}'.", t),
            Expected(exp, got) => write!(f, "Invalid cbor: not the right type, expected `{:?}' byte received `{:?}'.", exp, got),
            IndefiniteLenNotSupported(t) => write!(f, "Invalid cbor: indefinite length not supported for cbor object of type `{:?}'.", t),
            UnknownLenType(byte) => write!(f, "Invalid cbor: not the right sub type: 0b{:05b}", byte),
            InvalidTextError(utf8_error) => write!(f, "Invalid cbor: expected a valid utf8 string text. {:?}", utf8_error),
            WriteError(write_error) => write!(f, "Invalid cbor: write error: {:?}.", write_error),
            CustomError(err) => write!(f, "Invalid cbor: {}", err)
        }
    }
}
