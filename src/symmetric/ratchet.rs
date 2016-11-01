//! This module implements ratcheting for use with an AuthenticatedEncryptorDecryptor.
//! 
//! # Cryptography
//! For the n'th message, the keys are hashed n times. The nonce is also hashed. In a system which does not allow for message loss and re-ordering, this provides forward secrecy for the symmetric keys as each key can be destroyed immediately after use. SHA-256 is used because this matches the key length of chacha20.

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

use sodiumoxide::crypto::hash::sha256;
use std::mem;
use std::u16;
use sodiumoxide;

/// Struct for storing a symmetric key alongside it's message number. From this information any later key can be derived.
/// Drop is implemented for this structure so that it's memory is zeroed out when it goes out of scope.
pub struct KeyIteration {
    /// A Key appropriate to use with an AuthenticatedEncryptorDecryptor
    key: sha256::Digest,
    /// The message number (the number of times that the initial shared secret was hashed)
    number: u16,
}

impl Drop for KeyIteration {
    /// A method called when the value goes out of scope. This implementation destroys the memory.
    fn drop(&mut self) {
        // delete the key
        let &mut sha256::Digest(ref mut key_value) = &mut self.key;
        sodiumoxide::utils::memzero(key_value);

        // delete the number. We have to use unsafe so that we can transmute from u16 to [u8]
        unsafe {
            let number: &mut [u8; 2] = mem::transmute::<&mut u16, &mut [u8; 2]>(&mut self.number);
            sodiumoxide::utils::memzero(number);
        }
    }
}

/// private utility function to get the data out of an sha256::Digest
fn get_data_from_digest(digest: &sha256::Digest) -> [u8; sha256::DIGESTBYTES] {
    let &sha256::Digest(return_val) = digest;

    return_val
}

/// private utility function to hash a Digest n times
#[allow(unused_variables)] // for loop iterator variable
fn hash_n_times(d: &sha256::Digest, n: u16) -> sha256::Digest {
    if n == 0 {
        return d.clone();
    }
        
    // perform first iteration of the loop here so that rust knows that digest is always initialised
    let mut digest = sha256::hash(&get_data_from_digest(&d));
    let mut digest_data = get_data_from_digest(&digest);
            
    for i in 1..n { // loops n-1 times
        digest = sha256::hash(&digest_data);
        digest_data = get_data_from_digest(&digest);
    };

    digest
}

impl KeyIteration {
    /// Construct the first key. in_key will usually be the shared secret resulting from an asymmetric key exchange
    pub fn first(in_key: &[u8]) -> KeyIteration {
        let out_key = sha256::hash(in_key);

        KeyIteration {
            key: out_key,
            number: 0,
        }
    }

    /// Get the n'th key from the current KeyIteration object.
    /// The n requested must be greater than or equal to the N of the KeyIteration object.
    pub fn nth_key(&self, new_n: u16) -> [u8; sha256::DIGESTBYTES] {
        assert!(self.number <= new_n);
        assert!(self.number < u16::max_value()); // we add 1 to it 

        if self.number == new_n {
            get_data_from_digest(&self.key)
        } else {
            get_data_from_digest( &hash_n_times(&self.key, new_n - (self.number + 1)) ) // the +1 because 0 = 1 hash
        }
    }

    /// shift the KeyIteration object to a later iteration. This cannot be undone.
    /// This is done so that future compromises cannot compromise messages under the older keys and as a performance optimisation to reduce the number of hashes required.
    /// As it cannot be undone, this should not be done until the previous iterations of the keys are no-longer needed: e.g. their messages have all been acknowledged.
    /// TODO: this is not thread-safe
    pub fn increase_iter_to(&mut self, new_n: u16) {
        assert!(self.number < new_n);
        assert!(self.number < u16::max_value()); // we add 1 to it

        self.key = hash_n_times(&self.key, new_n - (self.number + 1)); // the +1 because 0 = 1 hash
        self.number = new_n;
    }
}

/******************* Tests *******************/
#[cfg(test)]
mod tests {
    use super::*;
    use sodiumoxide::randombytes;
    use sodiumoxide::crypto::hash::sha256;
    extern crate sodiumoxide;

    #[test]
    #[should_panic]
    #[allow(unused_must_use)] // the panic line looks unused
    fn nth_key_bad_n() {
        sodiumoxide::init();
        let key0 = &randombytes::randombytes(32);
        let mut key_iteration = KeyIteration::first(key0);
        key_iteration.increase_iter_to(5);

        // panic:
        key_iteration.nth_key(4);
    }

    #[test]
    fn first() {
        sodiumoxide::init();
        let key = &randombytes::randombytes(32);
        let key_iteration = KeyIteration::first(&key);

        assert_eq!(sha256::hash(&key), key_iteration.key);
        assert_eq!(0, key_iteration.number);
    }

    #[test]
    fn nth_key() {
        sodiumoxide::init();
        let key = &randombytes::randombytes(32);
        let key3 = KeyIteration::first(&key).nth_key(3);
        // hash three times
        let expected_key = sha256::hash( &super::get_data_from_digest(&sha256::hash( &super::get_data_from_digest(&sha256::hash(&key)))));

        assert_eq!(expected_key, sha256::Digest(key3));
    }

    #[test]
    fn increase_iter_to() {
        sodiumoxide::init();
        let key0 = &randombytes::randombytes(32);
        let mut key_iteration = KeyIteration::first(key0);
        key_iteration.increase_iter_to(3);
        // hash three times
        let expected_key = sha256::hash( &super::get_data_from_digest(&sha256::hash( &super::get_data_from_digest(&sha256::hash(&key0)))));

        assert_eq!(expected_key, key_iteration.key);
        assert_eq!(3, key_iteration.number);
    }
}
    
