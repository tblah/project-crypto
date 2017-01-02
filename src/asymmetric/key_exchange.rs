//! Key exchange module
//! 
//! This module performs the cryptography for the asymmetric key exchange. 
//!
//! Key exchange is implemented as suggested here https://download.libsodium.org/doc/advanced/scalar_multiplication.html

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

use super::*;
use super::super::symmetric::Digest;
use sodiumoxide::crypto::scalarmult::curve25519;
use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::utils::memzero;
use sodiumoxide::randombytes;

/// Generate an asymmetric key pair.
pub fn gen_keypair() -> (PublicKey, SecretKey) {
    let mut sk_bytes_raw = randombytes::randombytes(sha256::BLOCKBYTES);
    let mut sk_hash = sha256::hash(&sk_bytes_raw);
    let &mut sha256::Digest(ref mut sk_bytes) = &mut sk_hash;

    let sk = curve25519::Scalar::from_slice(&sk_bytes[0..curve25519::SCALARBYTES]).unwrap();
    let pk = curve25519::scalarmult_base(&sk);

    memzero(sk_bytes); // also kills off sk_hash
    memzero(sk_bytes_raw.as_mut_slice());

    (pk, sk) // both implement drop() to clear the memory so don't worry about them being copied
}

/// Function to perform key exchange.
///
/// The second public key is for key derivation from the X-co-ordinate, which alone does not possess enough entropy.
/// See https://download.libsodium.org/doc/advanced/scalar_multiplication.html
pub fn key_exchange(pub_key: &PublicKey, sec_key: &SecretKey, other_pub_key: &PublicKey, is_client: bool) -> Digest {
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

/******************* Tests *******************/
#[cfg(test)]
mod tests {
    use super::*;
    extern crate sodiumoxide;

   #[test]
   fn key_exchange_test() {
        sodiumoxide::init();
        
        let (pk1, sk1) = gen_keypair();
        let (pk2, sk2) = gen_keypair();

        let k1 = key_exchange(&pk2, &sk1, &pk1, true);
        let k2 = key_exchange(&pk1, &sk2, &pk2, false);

        assert_eq!(k1, k2);
    }
}
