//! This module provides an implementation of AuthenticatedEncryptorDecryptor.
//! 
//! # Cryptography
//! Authenticates *first* with HMAC-SHA512 (only the first 256 bytes are used). This was chosen as it is the default authentication mechanism in sodiumoxide.
//! Then we encrypt using ChaCha20. ChaCha20 over the sodiumoxide default (xsalsa20) because I will not be using a random nonse and chacha is more resistant to crypt analysis (see it's introductory paper). The key is used directly. You most likely want to hash it before using it here. You may need to also hash the nonce before using it here.
//!
//! # Example
//! ```
//! # extern crate sodiumoxide;
//! # extern crate proj_crypto;
//! # use proj_crypto::symmetric::chacha20hmacsha512256::*;
//! use sodiumoxide::crypto::stream::chacha20;
//! use sodiumoxide::crypto::auth::hmacsha512256;
//! use std::str;
//! 
//! # fn main() {
//! sodiumoxide::init();
//! let e_k = chacha20::gen_key();       // encryption key
//! let a_k = hmacsha512256::gen_key();  // authentication key
//! let nonce = chacha20::gen_nonce();   // nonce
//! let dut = ChaCha20HmacSha512256::new(e_k, a_k, nonce);
//!
//! let message = "hello world!";
//!
//! let ciphertext = dut.authenticate_and_encrypt(message.as_bytes());
//!
//! let transmitted_message = dut.decrypt_and_authenticate(&ciphertext).unwrap();
//!
//! assert_eq!(message, str::from_utf8(&transmitted_message).unwrap());
//! # }

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

use sodiumoxide::crypto::stream::chacha20;
use sodiumoxide::crypto::auth::hmacsha512256;

pub use super::AuthenticatedEncryptorDecryptor;

/// Struct for storing the state of the symmetric encryption and authentication system.
/// You do not need to worry about destroying these data properly as this is done within sodiumoxide whenever it's types go out of scope.
pub struct ChaCha20HmacSha512256 {
    encryption_key: chacha20::Key,
    authentication_key: hmacsha512256::Key,
    nonce: chacha20::Nonce,
}

impl ChaCha20HmacSha512256 {
    /// Constructor for ChaCha20HmacSha512256.
    ///
    /// # Example
    /// ```
    /// # extern crate sodiumoxide;
    /// # extern crate proj_crypto;
    ///
    /// # use proj_crypto::symmetric::chacha20hmacsha512256::ChaCha20HmacSha512256;
    /// use sodiumoxide::crypto::stream::chacha20;
    /// use sodiumoxide::crypto::auth::hmacsha512256;
    /// 
    /// # fn main() {
    /// sodiumoxide::init();
    /// ChaCha20HmacSha512256::new( chacha20::gen_key(), hmacsha512256::gen_key(), chacha20::gen_nonce() );
    /// # }
    /// ``` 
    pub fn new(encryption_key: chacha20::Key, authentication_key: hmacsha512256::Key, nonce: chacha20::Nonce) -> ChaCha20HmacSha512256 {
        ChaCha20HmacSha512256 {
            encryption_key: encryption_key,
            authentication_key: authentication_key,
            nonce: nonce,
        }
    }
}

impl AuthenticatedEncryptorDecryptor for ChaCha20HmacSha512256 {
    fn authenticate_and_encrypt(&self, message: &[u8]) -> Vec<u8> {
        let auth_tag = hmacsha512256::authenticate(message, &self.authentication_key);
        let hmacsha512256::Tag(ref auth_slice) = auth_tag;

        let mut cleartext = vec![];
        cleartext.extend_from_slice(message);
        cleartext.extend_from_slice(auth_slice);

        chacha20::stream_xor(&cleartext, &self.nonce, &self.encryption_key)
    }

    fn decrypt_and_authenticate(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        assert!(ciphertext.len() > hmacsha512256::TAGBYTES);

        let plaintext = chacha20::stream_xor(ciphertext, &self.nonce, &self.encryption_key);
        let (message, auth_tag) = plaintext.split_at(ciphertext.len() - hmacsha512256::TAGBYTES);

        if hmacsha512256::verify(&hmacsha512256::Tag::from_slice(auth_tag).unwrap(), message, &self.authentication_key) {
            let mut ret = vec![];
            ret.extend_from_slice(message);
            Some(ret)
        } else {
            None
        }
    }
}

/******************** Tests ******************/
#[cfg(test)]
mod tests {
    use super::*;
    use sodiumoxide::crypto::stream::chacha20;
    use sodiumoxide::crypto::auth::hmacsha512256;
    use std::str;

    #[test]
    fn new() {
        let k_e = chacha20::gen_key();
        let k_a = hmacsha512256::gen_key();
        let nonce = chacha20::gen_nonce();
        let dut = ChaCha20HmacSha512256::new(k_e.clone(), k_a.clone(), nonce.clone());

        assert_eq!(k_e, dut.encryption_key);
        assert_eq!(k_a, dut.authentication_key);
        assert_eq!(nonce, dut.nonce);
    }

    #[test]
    fn authenticated_encryptor_decryptor() {
        let e_k = chacha20::gen_key();
        let a_k = hmacsha512256::gen_key();
        let nonce = chacha20::gen_nonce();
        let dut = ChaCha20HmacSha512256::new(e_k.clone(), a_k.clone(), nonce.clone());

        let message = "hello world!";

        let ciphertext = dut.authenticate_and_encrypt(message.as_bytes());

        let transmitted_message = dut.decrypt_and_authenticate(&ciphertext).unwrap();

        assert_eq!(message, str::from_utf8(&transmitted_message).unwrap());
    }

    #[test]
    #[should_panic]
    fn authenticated_encryptor_decryptor_corrupted_auth() {
        let e_k = chacha20::gen_key();
        let a_k = hmacsha512256::gen_key();
        let a_k2 = hmacsha512256::gen_key();
        let nonce = chacha20::gen_nonce();
        let dut = ChaCha20HmacSha512256::new(e_k.clone(), a_k.clone(), nonce.clone());
        let dut_corrupted = ChaCha20HmacSha512256::new(e_k.clone(), a_k2.clone(), nonce.clone());

        let message = "hello world!";

        let ciphertext = dut.authenticate_and_encrypt(message.as_bytes());

        let transmitted_message = dut_corrupted.decrypt_and_authenticate(&ciphertext).unwrap();

        assert_eq!(message, str::from_utf8(&transmitted_message).unwrap());
    }

    #[test]
    #[should_panic]
    fn authenticated_encryptor_decryptor_corrupted_enc() {
        let e_k = chacha20::gen_key();
        let e_k2 = chacha20::gen_key();
        let a_k = hmacsha512256::gen_key();
        let nonce = chacha20::gen_nonce();
        let dut = ChaCha20HmacSha512256::new(e_k.clone(), a_k.clone(), nonce.clone());
        let dut_corrupted = ChaCha20HmacSha512256::new(e_k2.clone(), a_k.clone(), nonce.clone());

        let message = "hello world!";

        let ciphertext = dut.authenticate_and_encrypt(message.as_bytes());

        let transmitted_message = dut_corrupted.decrypt_and_authenticate(&ciphertext).unwrap();

        assert_eq!(message, str::from_utf8(&transmitted_message).unwrap());
    }
}
