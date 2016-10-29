//! Symmetric encryption module.
//! 
//! This module provides an interface for symmetric (secret key) cryptography. 

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

/// Trait representing something that does symmetric authenticated encryption.
pub trait AuthenticatedEncryptorDecryptor {
    /// Authenticates the message and then encrypts the message and the authentication token. The result is returned as a vector.
    fn authenticate_and_encrypt(&self, message: &[u8]) -> Vec<u8>;

    /// Decrypts the cipher text and then attempts to authenticate it. 
    fn decrypt_and_authenticate(&self, ciphertext: &[u8]) -> Option<Vec<u8>>;
}

/// Module containing an in implementation of AuthenticatedEncryptorDecryptor. 
pub mod chacha20hmacsha512256;


pub mod ratchet;
