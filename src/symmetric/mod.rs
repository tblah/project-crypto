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
//! Then we encrypt using ChaCha20. ChaCha20 was chosen over the sodiumoxide default (xsalsa20) because I will not be using a random nonse and chacha is more resistant to crypt analysis (see it's introductory paper). The key is used from the ratcheting system.
//!
//! # Example (Encrypted Authentication)
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
//! let message_number: u16 = 0;
//!
//! let mut state = State::new(k_e, k_a);
//! let ciphertext = state.authenticated_encryption(message.as_bytes(), message_number);
//! let plaintext = state.authenticated_decryption(&ciphertext, message_number).unwrap();
//!
//! assert_eq!(message, str::from_utf8(&plaintext).unwrap());
//!
//! // some stuff happens. Now we no-longer need keys for messages numbered less than 8
//!
//! state.increase_iter_to(8);
//!
//! // crypto still works for message numbers starting from 8:
//! let ciphertext8 = state.authenticated_encryption(message.as_bytes(), 8);
//! let plaintext8 = state.authenticated_decryption(&ciphertext8, 8).unwrap();
//!
//! assert_eq!(message, str::from_utf8(&plaintext8).unwrap());
//! # }
//! ```
//!
//! # Example (Plain Authentication)
//! ```
//! # extern crate sodiumoxide;
//! # extern crate proj_crypto;
//! # use proj_crypto::symmetric::*;
//! use sodiumoxide::randombytes;
//! use std::str;
//! 
//! # fn main() {
//! sodiumoxide::init();
//! let message = "hello world!".as_bytes();
//! let k_e = &randombytes::randombytes(32);
//! let k_a = &randombytes::randombytes(32);
//! let message_number: u16 = 0;
//!
//! let mut state = State::new(k_e, k_a);
//! let state = State::new(k_e, k_a);
//! let auth_tag = state.plain_auth_tag(message, message_number);
//!
//! assert!( state.verify_auth_tag(&auth_tag, message, message_number) );
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
/// Memory is zeroed when this goes out of scope
pub struct State {
    encryption_key: KeyIteration, // implements drop()
    authentication_key: KeyIteration, // implements drop()
}

impl State {
    /// Create a new symmetric::State object.
    pub fn new(encryption_key: &[u8], authentication_key: &[u8]) -> State {
        State {
            encryption_key: KeyIteration::first(encryption_key),
            authentication_key: KeyIteration::first(authentication_key),
        }
    }

    /// (private) Creates a new ChaCha20HmacSha512256 object
    fn create_encryption_object(&self, message_number: u16) -> ChaCha20HmacSha512256 {
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

    /// Attempt authenticated decryption.
    /// Similar semantics to encryption.
    pub fn authenticated_decryption(&self, ciphertext: &[u8], message_number: u16) -> Option<Vec<u8>> {
        self.create_encryption_object(message_number).decrypt_and_authenticate(ciphertext)
    }

    /// Un-encrypted authentication for verifying public packet metadata such as the message number and length
    pub fn plain_auth_tag(&self, message: &[u8], message_number: u16) -> [u8; hmacsha512256::TAGBYTES] {
        self.create_encryption_object(message_number).plain_auth_tag(message)
    }

    /// for verifying tags created by plain_auth_tag
    pub fn verify_auth_tag(&self, auth_tag: &[u8], message: &[u8], message_number: u16) -> bool {
        // auth_tag is verified in ChaCha20HmacSha512256
        self.create_encryption_object(message_number).verify_auth(auth_tag, message)
    }
 
    /// Destroy keys up to number n.
    /// This is done so that future compromises cannot compromise messages under the older keys and as a performance optimisation to reduce the number of hashes required.
    /// As it cannot be undone, this should not be done until the previous iterations of the keys are no-longer needed: for example their messages have all been acknowledged.
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
    fn encrypt_decrypt_zero() {
        sodiumoxide::init();
        let message = "hello world!";
        let k_e = &randombytes::randombytes(32);
        let k_a = &randombytes::randombytes(32);
        let message_number: u16 = 0; // important to test the boundary


        let state = State::new(k_e, k_a);
        let ciphertext = state.authenticated_encryption(message.as_bytes(), message_number);
        let plaintext = state.authenticated_decryption(&ciphertext, message_number).unwrap();

        assert_eq!(message, str::from_utf8(&plaintext).unwrap());
    }

    fn random_message_number() -> u16 {
        let message_number_bytes = randombytes::randombytes(2);
        let mut message_number: u16 = 0;

        // turn two bytes into a u16
        message_number |= ((message_number_bytes[0]) as u16) << 8;
        message_number |= (message_number_bytes[1]) as u16;

        // check the message number is valid
        if message_number == u16::max_value() {
            random_message_number() // generate a new one
        } else {
            message_number // this one is good enough
        }
    }


    #[test]
    fn encrypt_decrypt_random() { // this might look like it would be slower but my i5-3570k can do 2 971 550 SHA512 hashes of this size in one second (openssl speed). This is a lot more than u16::max_value()
        sodiumoxide::init();
        let message = "hello world!";
        let k_e = &randombytes::randombytes(32);
        let k_a = &randombytes::randombytes(32);
        let message_number = random_message_number();

        let state = State::new(k_e, k_a);
        let ciphertext = state.authenticated_encryption(message.as_bytes(), message_number);
        let plaintext = state.authenticated_decryption(&ciphertext, message_number).unwrap();

        assert_eq!(message, str::from_utf8(&plaintext).unwrap());
    }

    #[test]
    fn plain_auth_random() {
        sodiumoxide::init();
        let message = "hello world!".as_bytes();
        let k_e = &randombytes::randombytes(32);
        let k_a = &randombytes::randombytes(32);
        let message_number = random_message_number();

        let state = State::new(k_e, k_a);
        let auth_tag = state.plain_auth_tag(message, message_number);

        assert!( state.verify_auth_tag(&auth_tag, message, message_number) );
    }

}
