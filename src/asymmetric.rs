//! Asymmetric Encryption Module. 
//! 
//! This module performs the cryptography for the asymmetric key exchange. It is pretty much the same as is used in Signal, explained here https://whispersystems.org/blog/advanced-ratcheting/.
//!
//! Basically the encryption shared secret is derived from ephemeral key pairs and authentication keys are the sender's long-term key pair exchanged with the receiver's ephemeral key pair. This is faster than signing and I think it is rather elegant too.
//!
//! # The Protocol
//! ## Device Message 0
//! +generate ephemeral keypair
//! +compute authentication key for receiving from the server
//! +send ephemeral key to the server
//!
//! ## Server Message 0
//! +Generate ephemeral keypair
//! +Compute all session keys
//! +Pick a random challenge number
//! +Send ephemeral public key and r to the client, plaintext authentication (as the client does not yet have the encryption key)
//!
//! ## Device Message 1
//! +Check auth
//! +Compute remaining session keys
//! Send r to server, encrypted and authenticated. This authenticates the ephemeral public key we sent in message 0
//!
//! ## Server
//! +Decrypt and authenticate and check the challenge response

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

use super::symmetric;
use sodiumoxide::crypto::scalarmult::curve25519;
use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::utils::memzero;
use sodiumoxide::randombytes;

/// Public Key - just an alias. GroupElement does implement drop() so the memory will be wiped when this goes out of scope
pub type PublicKey = curve25519::GroupElement; 

/// Secret Key - just an alias. Sclar does implement drop() so the memory will be wiped when this goes out of scope
pub type SecretKey = curve25519::Scalar;

/// generate a key pair
/// TODO clear memory properly
pub fn gen_keypair() -> (PublicKey, SecretKey) {
    let sk_bytes = &randombytes::randombytes(curve25519::SCALARBYTES);
    
    let sk = curve25519::Scalar::from_slice(sk_bytes).unwrap();
    let pk = curve25519::scalarmult_base(&sk);

    (pk, sk)
}

/// Stores long term keys (e.g. from a certificate authority)
/// The secret key is safely erased from memory when this goes out of scope
pub struct LongTermKeys {
    my_public_key: PublicKey,
    my_secret_key: SecretKey, // implements drop to safely destroy when this goes out of scope
    their_public_key: PublicKey,
}

/// stores session keys
pub struct SessionKeys {
    from_device: symmetric::State,
    from_server: symmetric::State,
}

const SHARED_SECRET_LENGTH: usize = sha256::DIGESTBYTES; // = 32 = (256 bits)

/// The length of the challenge sent by the server to the client
pub const CHALLENGE_BYTES: usize = 32;

const DEVICE_ENC_KEY_CONSTANT: &'static [u8] = b"device";
const SERVER_ENC_KEY_CONSTANT: &'static [u8] = b"server";

/// private function to perform key exchange.
/// The second public key is for key derivation from the X-co-ordinate, which alone does not possess enough entropy.
/// see https://download.libsodium.org/doc/advanced/scalar_multiplication.html
fn key_exchange(pub_key: &PublicKey, sec_key: &SecretKey, other_pub_key: &PublicKey, is_client: bool) -> [u8; SHARED_SECRET_LENGTH] {
    // scalar multiplication along curve25519. Gives an X co-ordinate of a point along the curve. 
    let point_on_curve = curve25519::scalarmult(sec_key, pub_key);
    let curve25519::GroupElement(ref point_on_curve_bytes) = point_on_curve;

    // extract references to the actual data
    let &curve25519::GroupElement(ref pub_key_bytes) = pub_key;
    let &curve25519::GroupElement(ref other_pub_key_bytes) = other_pub_key;

    // the shared key will be hash(point_on_curve || pubkey1 || pubkey2)
    let mut thing_to_hash = vec![];
    thing_to_hash.extend_from_slice(point_on_curve_bytes);
    if is_client {
        thing_to_hash.extend_from_slice(pub_key_bytes);
        thing_to_hash.extend_from_slice(other_pub_key_bytes);
    } else {
        thing_to_hash.extend_from_slice(other_pub_key_bytes);
        thing_to_hash.extend_from_slice(pub_key_bytes);
    }

    // finally work out the shared secret
    let sha256::Digest(shared_secret) = sha256::hash(&thing_to_hash);

    // clean up memory. unsafe to ignore mutability check
    // point_on_curve is destroyed when it goes out of scope as it implements it in GroupElement::drop()
    memzero(&mut thing_to_hash);

    shared_secret // returned by value so this memory is never cleaned up!!! TODO!
}

fn hash_two_things(thing1: &[u8], thing2: &[u8]) -> [u8; SHARED_SECRET_LENGTH] {
    let mut thing_to_hash = vec![];
    thing_to_hash.extend_from_slice(thing1);
    thing_to_hash.extend_from_slice(thing2);

    let sha256::Digest(result) = sha256::hash(&thing_to_hash);

    memzero(&mut thing_to_hash);

    result // returned by value so this memory is never cleaned up!! TODO!
}

impl LongTermKeys {
    /// the first message from the device. This initiates the exchange
    /// returns: (ephemeral public key, ephemeral secret key, key for authenticating messages sent by the server)
    pub fn device_first(&self) -> (PublicKey, SecretKey, [u8; SHARED_SECRET_LENGTH]) {
        // generate ephemeral keypair
        let (pub_key, sec_key) = gen_keypair(); // don't worry, sec_key implements drop() to clear memory

        // key exchange between the server's public key and the ephemeral private key
        let auth_from_server = key_exchange(&self.their_public_key, &sec_key, &pub_key, true);

        (pub_key, sec_key, auth_from_server)
    }

    /// the first message from the server. This comes after receiving the first message from the device.
    /// Returns the ephemeral public key, the random challenge, the session keys and the authentication tag to send to the device, the plaintext to send to the device
    pub fn server_first(&self, device_ephemeral_public: &PublicKey, message_number: u16) -> (PublicKey, Vec<u8>, SessionKeys, [u8; symmetric::AUTH_TAG_BYTES], Vec<u8>) {
        // generate ephemeral keypair
        let (pub_key, sec_key) = gen_keypair(); // sec_key implements drop() to clear memory
        
        let random_challenge = randombytes::randombytes(CHALLENGE_BYTES);
        
        // we need different encryption keys in each direction because the message number is used as a nonce and both sides maintain separate message number counts
        let mut encryption_key_shared = key_exchange(device_ephemeral_public, &sec_key, &pub_key, false);
        let device_enc_key = hash_two_things(&encryption_key_shared, DEVICE_ENC_KEY_CONSTANT);
        let server_enc_key = hash_two_things(&encryption_key_shared, SERVER_ENC_KEY_CONSTANT);

        let session_keys = SessionKeys {
            from_device: symmetric::State::new(&device_enc_key, &key_exchange(&self.their_public_key, &sec_key, &pub_key, false)),
            from_server: symmetric::State::new(&server_enc_key, &key_exchange(device_ephemeral_public, &self.my_secret_key, &self.my_public_key, false)), // TODO: is this the right other_pub_key?
        };

        // ciphertext to send to the device
        let curve25519::GroupElement(ref pub_key_bytes) = pub_key.clone();
        let mut plaintext = vec![];
        plaintext.extend_from_slice(pub_key_bytes);
        plaintext.extend_from_slice(&random_challenge);
        let auth_tag = session_keys.from_server.plain_auth_tag(&plaintext, message_number);
    
        // clean things up
        memzero(&mut encryption_key_shared);

        // return stuff
        (pub_key, random_challenge, session_keys, auth_tag, plaintext)
    } // session secret key destroyed when it goes out of scope here

}
         
/******************* Tests *******************/
#[cfg(test)]
mod tests {
    use super::*;
    use super::super::symmetric;
    extern crate sodiumoxide;
    use sodiumoxide::crypto::sign::ed25519;
    use sodiumoxide::randombytes;
    use sodiumoxide::crypto::scalarmult::curve25519;

   #[test]
    fn key_exchange_test() {
        let (pk1, sk1) = gen_keypair();
        let (pk2, sk2) = gen_keypair();

        let k1 = super::key_exchange(&pk2, &sk1, &pk1, true);
        let k2 = super::key_exchange(&pk1, &sk2, &pk2, false);

        assert_eq!(k1, k2);
    }
    
    #[test]
    #[allow(unused_variables)]
    fn auth_from_server() {
        sodiumoxide::init();

        // device long keypair
        let (d_pk, d_sk) = gen_keypair();

        // server long keypair
        let (s_pk, s_sk) = gen_keypair();

        let device = LongTermKeys {
            my_public_key: d_pk.clone(),
            my_secret_key: d_sk,
            their_public_key: s_pk.clone(),
        };

        let server = LongTermKeys {
            my_public_key: s_pk.clone(),
            my_secret_key: s_sk,
            their_public_key: d_pk.clone(),
        };

        let (d_pk_session, d_sk_session, auth_from_server) = device.device_first();
        let (s_pk_session, challenge, session_keys, auth_tag, plaintext) = server.server_first(&d_pk_session, 0);

        // we can't access the auth_from_server key calculated by the server directly so try authenticating with both of them
        let message = &randombytes::randombytes(32);
        let k_e = &randombytes::randombytes(32); // just needed so that we can make the symmetric::state object
        let message_number = 0;

        let auth_tag = session_keys.from_server.plain_auth_tag(message, message_number);

        let dummy_device_state = symmetric::State::new(k_e, &auth_from_server);

        assert!( dummy_device_state.verify_auth_tag(&auth_tag, message, message_number) );
    }
}
