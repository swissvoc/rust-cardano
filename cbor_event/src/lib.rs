//! # CBOR event library
//!
//! [`RawCbor`]: ./de/struct.RawCbor.html
//! [`Deserialize`]: ./de/trait.Deserialize.html
//! [`Serializer`]: ./se/struct.Serializer.html
//! [`Serialize`]: ./se/trait.Serialize.html
//! [`std::io::Write`]: https://doc.rust-lang.org/std/io/trait.Write.html
//! [`Error`]: ./enum.Error.html
//! [`Type`]: ./enum.Type.html
//!
//! `cbor_event` is a minimalist CBOR implementation of the CBOR binary
//! serialisation format. It provides a simple yet efficient way to parse
//! CBOR without the need for an intermediate type representation.
//!
//! Here is the list of supported CBOR primary [`Type`]:
//!
//! - Unsigned and Negative Integers;
//! - Bytes and UTF8 String (**finite length only**);
//! - Array and Map (of finite and indefinite size);
//! - Tag;
//! - Specials (`bool`, `null`... **except floating points**).
//!
//! ## Raw deserialisation: [`RawCbor`]
//!
//! Deserialisation works by consuming a `RawCbor` content. To avoid
//! performance issues some objects use a reference to the original
//! source [`RawCbor`] internal buffer. They are then linked to the object
//! by an associated lifetime, this is true for `Bytes`.
//!
//! ```
//! use cbor_event::de::*;
//!
//! let vec = &[0x43, 0x01, 0x02, 0x03][..];
//! let mut raw = RawCbor::from(vec);
//! let bytes = raw.bytes().unwrap();
//!
//! # assert_eq!(bytes.as_ref(), [1,2,3].as_ref());
//! ```
//!
//! For convenience, we provide the trait [`Deserialize`] to help writing
//! simpler deserializers for your types.
//!
//! ## Serialisation: [`Serializer`]
//!
//! To serialise your objects into CBOR we provide a simple object
//! [`Serializer`]. It is configurable with any [`std::io::Write`]
//! objects. [`Serializer`] is meant to be simple to use and to have
//! limited overhead.
//!

// Support using cbor_event without the standard library!
#![cfg_attr(not(feature = "std"), no_std)]

mod result;
mod error;
mod types;
mod len;
pub mod de;
pub mod se;

#[cfg(feature = "std")]
mod value;
mod macros;

pub use len::{*};
pub use types::{*};
pub use result::{Result};
pub use error::{Error};
pub use de::{Deserialize};
pub use se::{Serialize};

#[cfg(feature = "std")]
pub use value::{ObjectKey, Value};

const MAX_INLINE_ENCODING : u64 = 23;

const CBOR_PAYLOAD_LENGTH_U8  : u8 = 24;
const CBOR_PAYLOAD_LENGTH_U16 : u8 = 25;
const CBOR_PAYLOAD_LENGTH_U32 : u8 = 26;
const CBOR_PAYLOAD_LENGTH_U64 : u8 = 27;

/// exported as a convenient function to test the implementation of
/// [`Serialize`](./se/trait.Serialize.html) and
/// [`Deserialize`](./de/trait.Deserialize.html).
///
#[cfg(feature = "std")]
pub fn test_encode_decode<V: Sized+PartialEq+Serialize+Deserialize>(v: &V) -> Result<bool> {
    let bytes = Serialize::serialize(v, se::Serializer::new_vec())?.finalize();

    let mut raw = de::RawCbor::from(&bytes);
    let v_ = Deserialize::deserialize(&mut raw)?;

    Ok(v == &v_)
}

mod internal {
    pub mod core {
        #[cfg(not(feature = "std"))]
        pub use core::*;
        #[cfg(feature = "std")]
        pub use std::*;
    }
    //#[cfg(feature = "std")]
    //pub use std::io::Write;

    #[derive(Debug)]
    pub enum WriteError {
        NotEnough
    }

    pub trait Write {
        fn write_all(&mut self, bytes: &[u8]) -> Result<(), WriteError>;
    }

    /*
    #[cfg(feature = "std")]
    impl Write for Vec<u8> {
        /// uses implementation of [`std::io::Write`](https://doc.rust-lang.org/std/io/trait.Write.html).
        fn write_all(&mut self, bytes: &[u8]) -> Result<(), WriteError> {
            use ::std::io;
            if io::Write::write_all(self, bytes).is_err() {
                Err(WriteError::NotEnough)
            } else {
                Ok(())
            }
        }
    }
    */
    #[cfg(feature = "std")]
    impl<T: ::std::io::Write> Write for T {
        /// uses implementation of [`std::io::Write`](https://doc.rust-lang.org/std/io/trait.Write.html).
        fn write_all(&mut self, bytes: &[u8]) -> Result<(), WriteError> {
            use ::std::io;
            if io::Write::write_all(self, bytes).is_err() {
                Err(WriteError::NotEnough)
            } else {
                Ok(())
            }
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    pub struct RefBuffer<'a> {
        pub buffer: &'a mut [u8],
        pub offset: usize,
    }
    impl<'a> From<&'a mut [u8]> for RefBuffer<'a> {
        fn from(buffer: &'a mut [u8]) -> Self { RefBuffer { buffer, offset: 0 }}
    }
    impl<'a> Write for RefBuffer<'a> {
        fn write_all(&mut self, bytes: &[u8]) -> Result<(), WriteError> {
            let to_write = bytes.len();
            let remaining = self.buffer.len() - self.offset;
            if to_write > remaining { return Err(WriteError::NotEnough); }
            self.buffer[self.offset..self.offset + to_write].copy_from_slice(bytes);
            self.offset += to_write;
            Ok(())
        }
    }
    impl<'a> AsRef<[u8]> for RefBuffer<'a> {
        fn as_ref(&self) -> &[u8] { &self.buffer[..self.offset] }
    }
    impl<'a, 'b> PartialEq<[u8]> for RefBuffer<'a> {
        fn eq(&self, lhs: &[u8]) -> bool { self.buffer[..self.offset] == lhs[..] }
    }
    impl<'a, 'b> PartialEq<&'b [u8]> for RefBuffer<'a> {
        fn eq(&self, lhs: &&'b[u8]) -> bool { self.buffer[..self.offset] == lhs[..] }
    }
}

pub use internal::{WriteError, Write, RefBuffer};
