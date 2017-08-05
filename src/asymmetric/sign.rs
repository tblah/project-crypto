//! Public Key Signatures
//!
//! Just re-exports of sodiumoxide

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

pub use sodiumoxide::crypto::sign::ed25519::*;
use sodiumoxide;
use std;
use std::fs::OpenOptions;
use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::io::Write;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::path::Path;
use std::fmt::Display;

fn to_utf8_hex<'a>(bytes: &[u8]) -> Vec<u8> {
    let strings: Vec<String> = bytes.into_iter()
        .map(|b| format!("{:02X}", b))
        .collect();

    let mut ret = Vec::new();
    ret.extend_from_slice(strings.join(" ").as_bytes());
    ret
}

/// Generate a keypair and put it into the specified file
/// This is not memory tidy. It would be difficult to clear the memory properly here and I don't think it matters too much because this doesn't connect to the network
pub fn key_gen_to_file<P: AsRef<Path> + Display + Clone>(file_path: P) where String: std::convert::From<P> {
    // write keypair file
    let option = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .mode(0o600) // rw-------
        .open(file_path.clone());

    let mut file = match option {
        Ok(f) => f,
        Err(e) => panic!("Opening file '{}' failed with error: {}", file_path, e),
    };

    sodiumoxide::init();
    let (pk, sk) = gen_keypair();

    // unwraps to make sure we panic if something doesn't work
    let _ = file.write(b"PK: ").unwrap();
    let _ = file.write(&to_utf8_hex(&pk[..])).unwrap();
    let _ = file.write(b"\nSK: ").unwrap();
    let _ = file.write(&to_utf8_hex(&sk[..])).unwrap();
    let _ = file.write(b"\n").unwrap(); // just looks a bit nicer if someone curious looks at the file

    // write public key file
    let pub_option = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .mode(0o600) // rw-------
        .open(String::from(file_path.clone()) + ".pub");

    let mut pub_file = match pub_option {
        Ok(f) => f,
        Err(e) => panic!("Opening file '{}' failed with error: {}", file_path, e),
    };

    let _ = pub_file.write(b"PK: ").unwrap();
    let _ = pub_file.write(&to_utf8_hex(&pk[..])).unwrap();
    let _ = pub_file.write(b"\n").unwrap();
}

fn hex_char_to_num(c: char) -> u8 {
    match c {
        '0' => 0,
        '1' => 1,
        '2' => 2,
        '3' => 3,
        '4' => 4,
        '5' => 5,
        '6' => 6,
        '7' => 7,
        '8' => 8,
        '9' => 9,
        'A' => 10,
        'B' => 11,
        'C' => 12,
        'D' => 13,
        'E' => 14,
        'F' => 15,
        _ => panic!("{} is not a hexadecimal digit", c),
    }
}

fn hex_to_byte(hex: Vec<char>) -> u8 {
    assert_eq!(hex.len(), 2);

    hex_char_to_num(hex[1]) | (hex_char_to_num(hex[0]) << 4)
}

/// returns a file so as to give it back to the caller (it was borrowed to get here)
fn get_key_from_file(mut file: fs::File, prefix: &str) -> Option<(fs::File, Vec<u8>)> {
    let prefix_expected = String::from(prefix) + ": ";
    let mut prefix_read_bytes: [u8; 4] = [0; 4]; // e.g. "PK: "

    match file.read(&mut prefix_read_bytes) {
        Ok(_) => (),
        Err(_) => return None,
    };

    if prefix_read_bytes != prefix_expected.as_bytes() {
        if prefix_read_bytes != [10, 0, 0, 0]  { // 10 (denary) is linefeed in ascii
            panic!("The prefix read (as bytes) was {:?}, we expected {:?} ('{}'). Is the file malformed?", prefix_read_bytes, prefix_expected.as_bytes(), prefix_expected);
        } else { // we just got a linefeed so there is nothing to read
            return None;
        }
    }

    let mut key_hex_vec = Vec::new();
    match file.read_to_end(&mut key_hex_vec) {
        Ok(_) => (),
        Err(e) => panic!("Error reading file: {}", e),
    };

    if prefix == "PK" {
        key_hex_vec.truncate(64 + 31); // 64 characters and 31 spaces
    } else {
        key_hex_vec.truncate(128 + 63); // 128 characters and 63 spaces
    }

    let key_hex: Vec<char> = String::from_utf8(key_hex_vec).unwrap().chars().collect();
 
    // split the hex string into pairs of of hex digits (bytes)
    let key: Vec<u8> = key_hex.split(|c| *c == ' ')
        .map(|x| x.to_vec())
        .map(|x| hex_to_byte(x))
        .collect();

    Some((file, key))
}

fn open_or_panic<P: AsRef<Path> + Display + Clone>(path: P) -> fs::File {
    match fs::File::open(path.clone()) {
        Ok(f) => f,
        Err(e) => panic!("Error opening file '{}': {}", path, e),
    }
}

/// Reads keys from a file. Returns (my_pk, my_sk)
pub fn get_keypair<P1: AsRef<Path> + Display + Clone>(my_keypair_path: P1) -> (PublicKey, SecretKey) {
    let my_keypair_file = open_or_panic(my_keypair_path);

    // get my keypair
    let (mut my_keypair_file, pk_bytes) = get_key_from_file(my_keypair_file, "PK").unwrap();

    // seek to the start of SK
    my_keypair_file.seek(SeekFrom::Start(4+64+31+1)).unwrap(); // 4 byte prefix + 64 bytes of hex + 31 spaces + newline
    let (_, sk_bytes) = get_key_from_file(my_keypair_file, "SK").unwrap();

    let my_pk = PublicKey::from_slice(&pk_bytes).unwrap();
    let my_sk = SecretKey::from_slice(&sk_bytes).unwrap();

    (my_pk, my_sk)
}

/// Reads a public key from a file
pub fn get_pubkey<P1: AsRef<Path> + Display + Clone>(their_pk_path: P1) -> PublicKey {
    let pk_file = open_or_panic(their_pk_path);

    // get the trusted public key
    let result = get_key_from_file(pk_file, "PK");

    let (_, pk_bytes) = result.unwrap();
    let their_pk = PublicKey::from_slice(&pk_bytes).unwrap();

    their_pk
}

/*********************** Tests **************************/
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::remove_file;
    extern crate sodiumoxide;
    extern crate test;
    use sodiumoxide::randombytes::randombytes;
    use self::test::Bencher;

    #[bench]
    fn sign_bench(b: &mut Bencher) {
        sodiumoxide::init();
        let (pk, sk) = gen_keypair();
        let data = randombytes(8);
        
        b.iter(|| sign(&data, &sk) );
    }

    #[test]
    fn key_files() {
        let test_file_path = "key_files_test_keyfile_deleteme";
        let test_file_path_pub = String::from(test_file_path) + ".pub";
        
        key_gen_to_file(test_file_path);
        let _ = get_keypair(test_file_path);
        let _ = get_pubkey(&test_file_path_pub);
        remove_file(test_file_path).unwrap();
        remove_file(test_file_path_pub).unwrap();
    }
}
