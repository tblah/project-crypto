//! symmetric.rs
//! 
//! This module will provide an interface for symmetric (secret key) cryptography as implemented in my project.
//! This project is licenced under GPL version 3 or (at your choice) any later version of the GPL published by the [Free Software Foundation](https://fsf.org)
//! 
//! TODO: document crypto

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

/// Trait representing something that does symmetric authenticated encryption
pub trait AuthenticatedEncryptorDecrypter {
    /// Authenticates the message and then encrypts the message and the authentication token. The result is returned as a vector
    fn authenticate_and_encrypt(&self, message: &[u8]) -> Vec<u8>;

    /// Decrypts the cipher text and then attempts to authenticate it
    fn decrypt_and_authenticate(&self, ciphertext: &[u8]) -> Option<Vec<u8>>;

    /// safely clear the sensetive material out of memory
    fn destory(&mut self);
}

pub struct ChaCha20HmacSha512256 {
    encryption_key: chacha20::Key,
    authentication_key: hmacsha512256::Key,
    nonse: chacha20::Nonce,
}

