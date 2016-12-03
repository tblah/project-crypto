//! Asymmetric encryption module.
//! 
//! self::key_exchange is re-exported for backwards compatibility. See that module for it's tests and documentation.

/*  This file is part of project-crypto.
    project-crypto is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    project-crypto is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with project-crypto.  If not, see http://www.gnu.org/licenses/.*/

pub mod key_exchange;
pub mod sign;

pub use self::key_exchange::*;

use sodiumoxide::crypto::scalarmult::curve25519;
use sodiumoxide::randombytes;
use sodiumoxide::utils::memzero;
use sodiumoxide::crypto::hash::sha512;

/// Public Key - just an alias. Implements drop() so the memory will be wiped when it goes out of scope
pub type PublicKey = curve25519::GroupElement; 
/// The number of bytes in a PublicKey
pub const PUBLIC_KEY_BYTES: usize = curve25519::GROUPELEMENTBYTES;
/// create a public key from a slice
pub fn public_key_from_slice(slice: &[u8]) -> Option<PublicKey> { curve25519::GroupElement::from_slice(slice) }

/// Secret Key - just an alias. Implements drop() so the memory will be wiped when it goes out of scope
pub type SecretKey = curve25519::Scalar;
/// The number of bytes in a SecretKey
pub const SECRET_KEY_BYTES: usize = curve25519::SCALARBYTES;
/// create a secret key from a slice
pub fn secret_key_from_slice(slice: &[u8]) -> Option<SecretKey> { curve25519::Scalar::from_slice(slice) }

/// Generate an asymmetric key pair.
pub fn gen_keypair() -> (PublicKey, SecretKey) {
    let mut sk_bytes_raw = randombytes::randombytes(sha512::BLOCKBYTES);
    let mut sk_hash = sha512::hash(&sk_bytes_raw);
    let &mut sha512::Digest(ref mut sk_bytes) = &mut sk_hash;

    // I don't know why but libsodium does this
    /*sk_bytes[0] &= 248;
    sk_bytes[31] &= 63;
    sk_bytes[31] |= 64;
    */ 
    let sk = curve25519::Scalar::from_slice(&sk_bytes[0..curve25519::SCALARBYTES]).unwrap();
    let pk = curve25519::scalarmult_base(&sk);

    memzero(sk_bytes); // also kills off sk_hash
    memzero(sk_bytes_raw.as_mut_slice());

    (pk, sk) // both implement drop() to clear the memory so don't worry about them being copied
}


