//! # Key ID module
//!
//! Used to select the correct public key from the other party from the set of known public keys

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
use std::collections::HashMap;
use std::hash;
use super::*;

/// Public Key - just an alias. Implements drop() so the memory will be wiped when it goes out of scope
/// The type of the identifier used to specify the other party's public key.
/// This has to be a custom struct so that I can implement std::hash::Hash
#[derive(PartialEq, Eq)]
pub struct PublicKeyId {
    digest: sha256::Digest,
}

impl hash::Hash for PublicKeyId {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.digest[..].hash(state)
    }
}

/// Given an identifier, attempts to find the correct public key to use in LongKeys.
pub fn find_public_key(id: &PublicKeyId, trusted_keys: &HashMap<PublicKeyId, PublicKey>) -> Option<PublicKey> {
    let pk = match trusted_keys.get(&id) {
        Some(k) => k,
        None => return None,
    };

    // check that the hash matches
    // note that sodiumoxide overrides == with a constant time operation 
    if &id_of_pk(&pk) != id {
        return None;
    }

    Some(pk.clone())
}

/// Calculate the ID of a public key
pub fn id_of_pk(pk: &PublicKey) -> PublicKeyId {
    PublicKeyId {
        digest: sha256::hash(&pk[..]),
    }
}

/******************* Tests *******************/
#[cfg(test)]
mod tests {
    use super::*;
    use super::super::*;
    extern crate sodiumoxide;
    use std::collections::HashMap;

    #[test]
    fn find_public_key_correct() {
        sodiumoxide::init();

        // keypairs
        let (me, one, two, three) = (gen_keypair(), gen_keypair(), gen_keypair(), gen_keypair());

        let mut db: HashMap<PublicKeyId, PublicKey> = HashMap::new();

        db.insert(id_of_pk(&one.0), one.0.clone());
        db.insert(id_of_pk(&two.0), two.0.clone());
        db.insert(id_of_pk(&three.0), three.0.clone());

        // say we get a connection from identity 'two'
        let _ = LongTermKeys {
            my_public_key: me.0,
            my_secret_key: me.1,
            their_public_key: find_public_key(&id_of_pk(&two.0), &db).unwrap(), // the unwrap is the test
        };

        // now that we have a LongTermKeys we can do the key exchange
    }

    #[test]
    #[should_panic]
    fn find_public_key_unknown() {
        sodiumoxide::init();

        // keypairs
        let (me, one, two, unknown) = (gen_keypair(), gen_keypair(), gen_keypair(), gen_keypair());

        let mut db: HashMap<PublicKeyId, PublicKey> = HashMap::new();

        db.insert(id_of_pk(&one.0), one.0.clone());
        db.insert(id_of_pk(&two.0), two.0.clone());

        let _ = LongTermKeys {
            my_public_key: me.0,
            my_secret_key: me.1,
            their_public_key: find_public_key(&id_of_pk(&unknown.0), &db).unwrap(), // the unwrap is the test
        };

        // now that we have a LongTermKeys we can do the key exchange
    }

    #[test]
    #[should_panic]
    fn find_public_key_bad_id() {
        sodiumoxide::init();

        // keypairs
        let (me, one, two, three) = (gen_keypair(), gen_keypair(), gen_keypair(), gen_keypair());

        let mut db: HashMap<PublicKeyId, PublicKey> = HashMap::new();

        db.insert(id_of_pk(&one.0), one.0.clone());
        db.insert(id_of_pk(&one.0), two.0.clone()); // here is the error
        db.insert(id_of_pk(&three.0), three.0.clone());

        // say we get a connection from identity 'two'
        let _ = LongTermKeys {
            my_public_key: me.0,
            my_secret_key: me.1,
            their_public_key: find_public_key(&id_of_pk(&two.0), &db).unwrap(), // the unwrap is the test
        };

        // now that we have a LongTermKeys we can do the key exchange
    }
}
