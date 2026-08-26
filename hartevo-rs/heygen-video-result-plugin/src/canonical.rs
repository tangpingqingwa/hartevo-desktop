use serde::Serialize;
use sha2::{Digest as ShaDigest, Sha256};

use crate::Digest;

pub(crate) fn digest_bytes(bytes: &[u8]) -> Digest {
    Digest::from_hex_unchecked(hex_encode(Sha256::digest(bytes).as_slice()))
}

pub(crate) fn digest_serializable<T: Serialize>(value: &T) -> Digest {
    let bytes = serde_json::to_vec(value).expect("canonical plugin value serializes");
    digest_bytes(&bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
