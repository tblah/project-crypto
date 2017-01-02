//! Asymmetric encryption module.
//! 
//! See submodules for documentation.
//!
//! Unfortunately key_exchange and sign have to use a different representation of the keypair because libsodium uses incompatible representations of the public key between signatures and key exchanges (public interface to curve25519_mult_base).
//! The types which are part of this module are appropriate for usage with key_exchange and key_id.

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
pub mod key_id;

use sodiumoxide::crypto::scalarmult::curve25519;

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





