//! Asymmetric Encryption Module. 
//! 
//! This module performs the cryptography for the asymmetric key exchange. It is pretty much the same as is used in Signal, explained here https://whispersystems.org/blog/advanced-ratcheting/.
//!
//! Basically the encryption shared secret is derived from ephemeral key pairs and authentication keys are the sender's long-term key pair exchanged with the receiver's ephemeral key pair. This is faster than signing and I think it is rather elegant too.
//!
//! Key exchange is implemented as suggested here https://download.libsodium.org/doc/advanced/scalar_multiplication.html
//!
//! # The Protocol
//! ## Device Message 0
//! + generate ephemeral keypair
//! + compute authentication key for receiving from the server
//! + send ephemeral key to the server
//!
//! ## Server Message 0
//! + Generate ephemeral keypair
//! + Compute all session keys
//! + Pick a random challenge number
//! + Send ephemeral public key and r to the client, plaintext authentication (as the client does not yet have the encryption key)
//!
//! ## Device Message 1
//! + Check auth
//! + Compute remaining session keys
//! + Send r to server, encrypted and authenticated. This authenticates the ephemeral public key we sent in message 0
//!
//! ## Server
//! + Decrypt and authenticate and check the challenge response
//!
//! ## An important note:
//! Authentication session keys are symmetric therefore either party can impersonate the other. In an interactive setting this is not a problem because the keys are fixed to only this pair and the other side would not be expecting to receive a message authenticated using their key. However, if Bob decided to publish all his key material he could fabricate messages which look to a third party as though they are sent by Alice. This was intentional in the design of Signal's key exchange because it gives both parties plausible deniability.
//!
//! # Example 
//! ```
//! # extern crate sodiumoxide;
//! # extern crate proj_crypto;
//! # use proj_crypto::asymmetric::*;
//! use sodiumoxide::randombytes;
//! use std::str;
//! 
//! # fn main() {
//! sodiumoxide::init();
//!
//! // device long keypair
//! let (d_pk, d_sk) = gen_keypair();
//!
//! // server long keypair
//! let (s_pk, s_sk) = gen_keypair();
//!
//! let device = LongTermKeys {
//!     my_public_key: d_pk.clone(),
//!     my_secret_key: d_sk,
//!     their_public_key: s_pk.clone(),
//! };
//!
//! let server = LongTermKeys {
//!     my_public_key: s_pk.clone(),
//!     my_secret_key: s_sk,
//!     their_public_key: d_pk.clone(),
//! };
//!
//! // First message from the device
//! let (d_pk_session, d_sk_session, auth_from_server) = device.device_first();
//!
//! // Message from the server
//! let (challenge, server_session_keys, auth_tag, plaintext) = server.server_first(&d_pk_session, 0);
//!
//! // Challenge response from the device
//! let (device_session_keys, ciphertext) = device.device_second(&plaintext, &auth_tag, &d_pk_session, &d_sk_session, &auth_from_server, 0, 1).unwrap();
//!
//! // server verifying the client's challenge response
//! assert!(server_verify_response(&server_session_keys, &ciphertext, 1, &challenge));
//!
//! // we cannot access the keys directly so let's just check that we can read messages sent by each-other
//! let message = "hello world!".as_bytes();
//! let msg_from_server = server_session_keys.from_server.authenticated_encryption(&message, 1);
//! let msg_from_device = device_session_keys.from_device.authenticated_encryption(&message, 2);
//!
//! let msg_recvd_server = server_session_keys.from_device.authenticated_decryption(&msg_from_device, 2).unwrap();
//! let msg_recvd_device = device_session_keys.from_server.authenticated_decryption(&msg_from_server, 1).unwrap();
//!
//! assert_eq!(msg_recvd_server, message);
//! assert_eq!(msg_recvd_device, message);
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

use super::symmetric;
use super::symmetric::Digest;
use sodiumoxide::crypto::scalarmult::curve25519;
use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::utils::memzero;
use sodiumoxide::randombytes;
use sodiumoxide::utils::memcmp;

/// Public Key - just an alias. Implements drop() so the memory will be wiped when it goes out of scope
pub type PublicKey = curve25519::GroupElement; 
/// The number of bytes in a PublicKey
pub const PUBLIC_KEY_BYTES: usize = curve25519::GROUPELEMENTBYTES;

/// Secret Key - just an alias. Implements drop() so the memory will be wiped when it goes out of scope
pub type SecretKey = curve25519::Scalar;
/// The number of bytes in a SecretKey
pub const SECRET_KEY_BYTES: usize = curve25519::SCALARBYTES;

/// Generate an asymmetric key pair.
pub fn gen_keypair() -> (PublicKey, SecretKey) {
    let mut sk_bytes = randombytes::randombytes(curve25519::SCALARBYTES);
    
    let sk = curve25519::Scalar::from_slice(&sk_bytes).unwrap();
    let pk = curve25519::scalarmult_base(&sk);

    memzero(sk_bytes.as_mut_slice());

    (pk, sk) // both implement drop() to clear the memory so don't worry about them being copied
}

/// Stores long term keys (e.g. from a certificate authority)
/// The secret key is safely erased from memory when this goes out of scope
pub struct LongTermKeys {
    /// This party's long term public key
    pub my_public_key: PublicKey,
    /// This party's long term secret key. Secret key implements drop so that it is wiped when it goes out of scope.
    pub my_secret_key: SecretKey, // implements drop to safely destroy when this goes out of scope
    /// The public key of the party we are communicating with
    pub their_public_key: PublicKey,
}

/// stores session keys
pub struct SessionKeys {
    /// symmetric state for using with messages to be sent or received from the device
    pub from_device: symmetric::State,
    /// symmetric state for using with messages to be sent or received from the server
    pub from_server: symmetric::State,
}

const SHARED_SECRET_LENGTH: usize = sha256::DIGESTBYTES; // = 32 = (256 bits)

/// The length of the challenge sent by the server to the client
pub const CHALLENGE_BYTES: usize = 32;

const DEVICE_ENC_KEY_CONSTANT: &'static [u8] = b"device";
const SERVER_ENC_KEY_CONSTANT: &'static [u8] = b"server";

/// private function to perform key exchange.
/// The second public key is for key derivation from the X-co-ordinate, which alone does not possess enough entropy.
/// See https://download.libsodium.org/doc/advanced/scalar_multiplication.html
fn key_exchange(pub_key: &PublicKey, sec_key: &SecretKey, other_pub_key: &PublicKey, is_client: bool) -> Digest {
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
    let shared_secret = Digest{ digest: sha256::hash(&thing_to_hash) };

    // clean up memory 
    // point_on_curve is destroyed when it goes out of scope as it implements it in GroupElement::drop()
    memzero(&mut thing_to_hash);

    shared_secret // Digest implements drop() to clear the memory so don't worry about copying
}

fn hash_two_things(thing1: &[u8], thing2: &[u8]) -> Digest {
    let mut thing_to_hash = vec![];
    thing_to_hash.extend_from_slice(thing1);
    thing_to_hash.extend_from_slice(thing2);

    let result = Digest{ digest: sha256::hash(&thing_to_hash) };

    memzero(&mut thing_to_hash);

    result // Digest implements drop() to clear the memory so don't worry about copying
}

impl LongTermKeys {
    /// The first message from the device. This initiates the exchange.
    ///
    /// Returns (ephemeral public key, ephemeral secret key, key for authenticating messages sent by the server)
    pub fn device_first(&self) -> (PublicKey, SecretKey, [u8; SHARED_SECRET_LENGTH]) {
        // generate ephemeral keypair
        let (pub_key, sec_key) = gen_keypair(); // don't worry, sec_key implements drop() to clear memory

        // key exchange between the server's public key and the ephemeral private key
        let auth_from_server = key_exchange(&self.their_public_key, &sec_key, &pub_key, true);

        (pub_key, sec_key, auth_from_server.as_slice())
    }

    /// the first message from the server. This comes after receiving the first message from the device.
    ///
    /// Returns (the random challenge, the session keys, the authentication tag to send to the device, the plaintext to send to the device)
    pub fn server_first(&self, device_ephemeral_public: &PublicKey, message_number: u16) -> (Vec<u8>, SessionKeys, [u8; symmetric::AUTH_TAG_BYTES], Vec<u8>) {
        // generate ephemeral keypair
        let (pub_key, sec_key) = gen_keypair(); // sec_key implements drop() to clear memory
        
        let random_challenge = randombytes::randombytes(CHALLENGE_BYTES);
        
        // we need different encryption keys in each direction because the message number is used as a nonce and both sides maintain separate message number counts
        let sha256::Digest(mut encryption_key_shared) = key_exchange(device_ephemeral_public, &sec_key, &pub_key, false).digest; // we can't use Digest::as_slice() here because we want mutability
        let device_enc_key = hash_two_things(&encryption_key_shared, DEVICE_ENC_KEY_CONSTANT);
        let server_enc_key = hash_two_things(&encryption_key_shared, SERVER_ENC_KEY_CONSTANT);

        let session_keys = SessionKeys {
            from_device: symmetric::State::new(&device_enc_key.as_slice(), &key_exchange(&self.their_public_key, &sec_key, &pub_key, false).as_slice()),
            from_server: symmetric::State::new(&server_enc_key.as_slice(), &key_exchange(device_ephemeral_public, &self.my_secret_key, &self.my_public_key, false).as_slice()), 
        };

        // ciphertext to send to the device
        let curve25519::GroupElement(ref pub_key_bytes) = pub_key.clone();
        let mut plaintext = vec![];
        plaintext.extend_from_slice(pub_key_bytes);
        plaintext.extend_from_slice(&random_challenge);
        let auth_tag = session_keys.from_server.plain_auth_tag(&plaintext, message_number);
    
        // clean things up
        memzero(&mut encryption_key_shared);
        // *_enc_key are Digests so they will destroy themselves.
        // session_keys implements drop() so we don't need to worry about that either

        // return stuff
        (random_challenge, session_keys, auth_tag, plaintext)
    } // ephemeral keys destroyed here :-)
    
    /// The second message sent by the device. As far as the device is concerned, the setup is complete after sending this.
    ///
    /// Returns None if the server's message is invalid and Some((session keys, ciphertext to send to the server)) if everything checks out
    pub fn device_second(&self, server_message: &Vec<u8>, auth_tag: &[u8; symmetric::AUTH_TAG_BYTES], ephemeral_pk: &PublicKey, ephemeral_sk: &SecretKey, from_server_auth: &[u8; SHARED_SECRET_LENGTH], server_message_n: u16, my_message_n: u16)
                         -> Option<(SessionKeys, Vec<u8>)> {
        // test the auth on the server's message
        let server_authenticator = symmetric::State::new(from_server_auth, from_server_auth); // just set the encryption key that we don't have (and won't use) as the same  
        if !server_authenticator.verify_auth_tag(auth_tag, server_message, server_message_n) {
            return None; // symmetric::State implements drop so don't worry about leaking here
        };

        // check message length and then split it into what we want
        assert_eq!(server_message.len(), PUBLIC_KEY_BYTES + CHALLENGE_BYTES);
        let (server_ephemeral_pk_bytes, random_challenge) = server_message.split_at(PUBLIC_KEY_BYTES);
        let server_ephemeral_pk = curve25519::GroupElement::from_slice(server_ephemeral_pk_bytes).unwrap();

        // different encryption keys for each direction
        let encryption_key_shared = key_exchange(&server_ephemeral_pk, ephemeral_sk, ephemeral_pk, true);
        let device_enc_key = hash_two_things(&encryption_key_shared.as_slice(), DEVICE_ENC_KEY_CONSTANT);
        let server_enc_key = hash_two_things(&encryption_key_shared.as_slice(), SERVER_ENC_KEY_CONSTANT);

        // calculate package the session keys (and calculate my authentication key)
        let session_keys = SessionKeys {
            from_device: symmetric::State::new(&device_enc_key.as_slice(), &key_exchange(&server_ephemeral_pk, &self.my_secret_key, &self.my_public_key, true).as_slice()),
            from_server: symmetric::State::new(&server_enc_key.as_slice(), from_server_auth),
        };

        // encrypt and authenticate the random challenge for sending to the server
        let ciphertext = session_keys.from_device.authenticated_encryption(random_challenge, my_message_n);
        
        Some((session_keys, ciphertext))
    } // encryption_key_shared, session_keys and *_enc_key destroy it's self when it is drop()'ed
}
 
/// For the server to verify the challenge response from the client. 
pub fn server_verify_response(session_keys: &SessionKeys, response: &Vec<u8>, message_number: u16, challenge: &Vec<u8>) -> bool {
    match session_keys.from_device.authenticated_decryption(response, message_number) {
        None => false,
        Some(c) => memcmp(challenge, &c), // constant time comparison
    }
}        

/******************* Tests *******************/
#[cfg(test)]
mod tests {
    use super::*;
    use super::super::symmetric;
    extern crate sodiumoxide;
    use sodiumoxide::randombytes;

   #[test]
    fn key_exchange_test() {
        sodiumoxide::init();
        
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
        let (challenge, session_keys, auth_tag, plaintext) = server.server_first(&d_pk_session, 0);

        // we can't access the auth_from_server key calculated by the server directly so try authenticating with both of them
        let message = &randombytes::randombytes(32);
        let k_e = &randombytes::randombytes(32); // just needed so that we can make the symmetric::state object
        let message_number = 0;

        let auth_tag = session_keys.from_server.plain_auth_tag(message, message_number);

        let dummy_device_state = symmetric::State::new(k_e, &auth_from_server);

        assert!( dummy_device_state.verify_auth_tag(&auth_tag, message, message_number) );
    }

    #[test]
    #[allow(unused_variables)]
    fn three_messages() {
        sodiumoxide::init();
        const MSG_LEN: usize = 32;

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
        let (challenge, server_session_keys, auth_tag, plaintext) = server.server_first(&d_pk_session, 0);
        let (device_session_keys, ciphertext) = device.device_second(&plaintext, &auth_tag, &d_pk_session, &d_sk_session, &auth_from_server, 0, 1).unwrap();

        // we cannot access the keys directly so let's just check that we can read messages sent by each-other
        let message = randombytes::randombytes(MSG_LEN);
        let msg_from_server = server_session_keys.from_server.authenticated_encryption(&message, 1);
        let msg_from_device = device_session_keys.from_device.authenticated_encryption(&message, 2);

        let msg_recvd_server = server_session_keys.from_device.authenticated_decryption(&msg_from_device, 2).unwrap();
        let msg_recvd_device = device_session_keys.from_server.authenticated_decryption(&msg_from_server, 1).unwrap();

        assert_eq!(msg_recvd_server, message);
        assert_eq!(msg_recvd_device, message);
    }

    #[test]
    #[allow(unused_variables)]
    fn device_auth_check() {
        sodiumoxide::init();

        // generate an incorrect server authentication key
        let false_auth_key_bytes = randombytes::randombytes(super::SHARED_SECRET_LENGTH);
        let mut false_auth_key: [u8; super::SHARED_SECRET_LENGTH] = [0; super::SHARED_SECRET_LENGTH];
        for i in 0..super::SHARED_SECRET_LENGTH {
            false_auth_key[i] = false_auth_key_bytes[i];
        }

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
        let (challenge, server_session_keys, auth_tag, plaintext) = server.server_first(&d_pk_session, 0);

        let result = device.device_second(&plaintext, &auth_tag, &d_pk_session, &d_sk_session, &false_auth_key, 0, 1);

        // authentication should have failed
        assert!(result.is_none());
    }

    #[test]
    fn full_exchange() {
        sodiumoxide::init();
        const MSG_LEN: usize = 32;

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
        let (challenge, server_session_keys, auth_tag, plaintext) = server.server_first(&d_pk_session, 0);
        let (device_session_keys, ciphertext) = device.device_second(&plaintext, &auth_tag, &d_pk_session, &d_sk_session, &auth_from_server, 0, 1).unwrap();

        // server verifying the client's challenge response
        assert!(server_verify_response(&server_session_keys, &ciphertext, 1, &challenge));

        // we cannot access the keys directly so let's just check that we can read messages sent by each-other
        let message = randombytes::randombytes(MSG_LEN);
        let msg_from_server = server_session_keys.from_server.authenticated_encryption(&message, 1);
        let msg_from_device = device_session_keys.from_device.authenticated_encryption(&message, 2);

        let msg_recvd_server = server_session_keys.from_device.authenticated_decryption(&msg_from_device, 2).unwrap();
        let msg_recvd_device = device_session_keys.from_server.authenticated_decryption(&msg_from_server, 1).unwrap();

        assert_eq!(msg_recvd_server, message);
        assert_eq!(msg_recvd_device, message);
    }

}
