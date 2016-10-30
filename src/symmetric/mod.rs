//! Symmetric encryption module.
//! 
//! This module provides an interface for symmetric (secret key) cryptography. 
//!
//! # Cryptography
//! ## Ratcheting
//! For the n'th message, the keys are hashed n times. The nonce is also hashed. In a system which does not allow for message loss and re-ordering, this provides forward secrecy for the symmetric keys as each key can be destroyed immediately after use. SHA-256 is used because this matches the key length of chacha20.
//!
//! ## Secure Channel
//! Authenticates *first* with HMAC-SHA512 (only the first 256 bytes are used). This was chosen as it is the default authentication mechanism in sodiumoxide.
//! Then we encrypt using ChaCha20. ChaCha20 over the sodiumoxide default (xsalsa20) because I will not be using a random nonse and chacha is more resistant to crypt analysis (see it's introductory paper). The key is used directly. You most likely want to hash it before using it here. You may need to also hash the nonce before using it here.
//!
//! # Example
//! ```
//! # extern crate sodiumoxide;
//! # extern crate proj_crypto;
//! # use proj_crypto::symmetric::*;
//! use sodiumoxide::randombytes;
//! use std::str;
//! 
//! # fn main() {
//! sodiumoxide::init();
//! let message = "hello world!";
//! let k_e = &randombytes::randombytes(32);
//! let k_a = &randombytes::randombytes(32);
//! let message_number: u16 = 2;
//!
//! let state = State::new(k_e, k_a);
//! let ciphertext = state.authenticated_encryption(message.as_bytes(), message_number);
//! let plaintext = state.authenticated_decryption(&ciphertext, message_number).unwrap();
//!
//! assert_eq!(message, str::from_utf8(&plaintext).unwrap());
//! # }
//! ```

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

mod chacha20hmacsha512256;
mod ratchet;

use self::ratchet::KeyIteration;
use self::chacha20hmacsha512256::ChaCha20HmacSha512256;
use self::chacha20hmacsha512256::AuthenticatedEncryptorDecryptor;
use sodiumoxide::crypto::stream::chacha20;
use sodiumoxide::crypto::auth::hmacsha512256;
use sodiumoxide::crypto::hash::sha256;
use std::mem;

/// Stores the state of the symmetric encryption system.
/// Both of the member objects clean themselves up properly when they go out of scope so we do not need to worry about that on this level
/// Allows KeyIteration to be wrapped around ChaCha20HmacSha512256
pub struct State {
    encryption_key: KeyIteration,
    authentication_key: KeyIteration,
}

impl State {
    /// Create a new symmetric::State object
    pub fn new(encryption_key: &[u8], authentication_key: &[u8]) -> State {
        State {
            encryption_key: KeyIteration::first(encryption_key),
            authentication_key: KeyIteration::first(authentication_key),
        }
    }

    /// (private) Creates a new ChaCha20HmacSha512256 object
    fn create_encryption_object(&self, message_number: u16) -> ChaCha20HmacSha512256 {
        // message number validity checking is done within KeyIteration

        // using unwraps because everything was designed to always be the correct length
        let e_k = chacha20::Key::from_slice( &self.encryption_key.nth_key(message_number) ).unwrap();
        let a_k = hmacsha512256::Key::from_slice( &self.authentication_key.nth_key(message_number) ).unwrap();

        let ret: ChaCha20HmacSha512256;

        unsafe { // unsafe because of the call to hash_message_number
            let nonce = chacha20::Nonce::from_slice( &hash_message_number(message_number) ).unwrap();
            ret = ChaCha20HmacSha512256::new(e_k, a_k, nonce);
        }

        ret
    }

    /// Perform authenticated encryption.
    /// The message number is used to select the correct encryption key and as a nonce.
    /// Returns the ciphertext.
    pub fn authenticated_encryption(&self, message: &[u8], message_number: u16) -> Vec<u8> {
        self.create_encryption_object(message_number).authenticate_and_encrypt(message)
    }

    /// Attempt authenticated decryption
    /// Similar semantics to encryption
    pub fn authenticated_decryption(&self, ciphertext: &[u8], message_number: u16) -> Option<Vec<u8>> {
        self.create_encryption_object(message_number).decrypt_and_authenticate(ciphertext)
    }
 
    /// Destroy keys up to number n.
    /// This is done so that future compromises cannot compromise messages under the older keys and as a performance optimisation to reduce the number of hashes required.
    /// As it cannot be undone, this should not be done until the previous iterations of the keys are no-longer needed: e.g. their messages have all been acknowledged.
    pub fn increase_iter_to(&mut self, new_n: u16) {
        self.encryption_key.increase_iter_to(new_n);
        self.authentication_key.increase_iter_to(new_n);
    }
       
}

/// hashes the message number to make the nonce (remove all the structure)
/// unsafe to allow the transmute operation from u16 to [u8] so that the message number can be hashed
unsafe fn hash_message_number(num: u16) -> [u8; chacha20::NONCEBYTES] {
    let n = mem::transmute::<u16, [u8; 2]>(num);
    let digest = sha256::hash(&n);
    let sha256::Digest(digest_data) = digest;

    // done in a clumsy-looking way so that this doesn't end up being a slice
    let mut ret: [u8; chacha20::NONCEBYTES] = [0; chacha20::NONCEBYTES];

    for i in 0..chacha20::NONCEBYTES {
        ret[i] = digest_data[i];
    }

    ret
}

/******************* Tests *******************/
#[cfg(test)]
mod tests {
    use super::*;
    use sodiumoxide::randombytes;
    extern crate sodiumoxide;
    use std::str;

    #[test]
    fn encrypt_decrypt() {
        sodiumoxide::init();
        let message = "hello world!";
        let k_e = &randombytes::randombytes(32);
        let k_a = &randombytes::randombytes(32);
        let message_number: u16 = 2;


        let state = State::new(k_e, k_a);
        let ciphertext = state.authenticated_encryption(message.as_bytes(), message_number);
        let plaintext = state.authenticated_decryption(&ciphertext, message_number).unwrap();

        assert_eq!(message, str::from_utf8(&plaintext).unwrap());
    }
}
