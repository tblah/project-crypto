//! Implementation of Pedersen's Commitment scheme 
//! http://download.springer.com/static/pdf/357/chp%253A10.1007%252F3-540-46766-1_9.pdf
//!
//! **The implementation here is likely to be particularly sketchy as I really do not understand the maths behind the discrete logarithm problem.
//! The advice not to use this for anything important holds particularly strongly here.**
//!
//! # Example - Homomorphic Commitments
//! This example demonstrates the homorphic properties of Pedersen Commitments.
//!
//! ```
//! # extern crate proj_crypto;
//! # extern crate sodiumoxide;
//! # extern crate gmp;
//! use proj_crypto::asymmetric::commitments::*;
//! use gmp::mpz::Mpz;
//! # use sodiumoxide::randombytes::randombytes;
//! # fn rand_u64() -> u64 {
//! #    let data_bytes = randombytes(8);
//! #    let mut data = 0 as u64;
//! #    for i in 0..8 {
//! #        data |= (data_bytes[i] as u64) << (i*8);
//! #    }   
//! #    data
//! # }
//!
//! # fn main() {
//! sodiumoxide::init();
//!
//! let co_eff1 = Mpz::from(rand_u64());
//! let co_eff2 = Mpz::from(rand_u64());
//! let data1 = Mpz::from(rand_u64());
//! let data2 = Mpz::from(rand_u64());
//! let result = data1.clone()*co_eff1.clone() + data2.clone()*co_eff2.clone(); // assume this does not become greater than p
//!
//! let params = gen_dh_params().unwrap(); // this step can take a long time
//! let a = random_a(&params.1);
//! let a_result = (a.clone()*co_eff1.clone() + a.clone()*co_eff2.clone()).modulus(&params.0);
//!
//! let context1 = CommitmentContext::from_opening((data1, a.clone()), params.clone()).unwrap();
//! let context2 = CommitmentContext::from_opening((data2, a.clone()), params.clone()).unwrap();
//! let context_result = CommitmentContext::from_opening((result, a_result), params.clone()).unwrap();
//!
//! let commit1 = context1.to_commitment();
//! let commit2 = context2.to_commitment();
//! let commit_result = context_result.to_commitment();
//!
//! let commit_blind_result = (commit1 * co_eff1) + (commit2 * co_eff2);
//!
//! assert!(commit_result == commit_blind_result);
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

use gmp::mpz::Mpz;
use gmp::rand;
use sodiumoxide::randombytes::randombytes;
use std::fs;
use std::path::Path;
use std::os::unix::fs::OpenOptionsExt;
use std::io;
use std::io::Write;
use std::io::BufRead;
use std::io::Error;
use std::io::ErrorKind;
use std::ops::Add;
use std::ops::Mul;
use std::cmp::{Eq, PartialEq};

/// The data required to open a commitment: the data committed to and the random integer a
pub type Opening = (Mpz, Mpz);

/// The commitment its self as one would share along a wire
#[derive(Clone)]
pub struct Commitment {
    /// The numerical representation of the commitment
    pub x: Mpz,
    /// We can't do any maths without p
    pub p: Mpz,
}

impl Commitment {
    /// Creates a Commitment from raw parts
    pub fn from_parts(x: Mpz, p: Mpz) -> Result<Commitment, ()> {
        if verify_p(&p) {
            return Ok( Commitment { x: x, p: p } );
        }

        Err(())
    }
}

/// A structure containing all the data relating to a commitment. This contains secrets. Drop has been implemented for Mpz to clear the memory when it goes out of scope.
pub struct CommitmentContext {
    /// A random integer modulo q. This is called the binding number. This is secret.
    a: Mpz,
    /// The value of the commitment its self
    pub commitment_value: Mpz,
    /// The value that was committed to. Obviously, this is a secret.
    data: Mpz,
    /// The diffie-hellman parameters used in the commitment. These can be disclosed publicly
    pub parameters: DHParams,
}

impl CommitmentContext {
    /// Output the opening of this commitment
    pub fn get_opening(&self) -> Opening {
        (self.data.clone(), self.a.clone())
    }

    /// Generate the commitment from the opening (deterministic)
    pub fn from_opening(opening: Opening, params: DHParams) -> Result<CommitmentContext, &'static str> {
        if !verify_dh_params(&params) {
            return Err("Bad parameters");
        }

        let (data, a) = opening;
        let &(ref p, ref q, ref g, ref h) = &params;

        if &data >= q {
            return Err("We can only commit to (data mod q)");
        }

        if &a >= p { // p because a may be arrived at by computations (mod p) and p > q
            return Err("Invalid a");
        }
        
        Ok(CommitmentContext {
            a: a.clone(),
            commitment_value: (h.powm(&data, &p) * g.powm(&a, &p)).modulus(&p),
            data: data,
            parameters: params.clone(),
        })
    }

    /// Generate a commitment onto some data (non-deterministic)
    pub fn from_data(data: Mpz, params: DHParams) -> Result<CommitmentContext, &'static str> {
        let a = random_a(&params.1);        
        Self::from_opening((data, a), params)
    }

    /// Return the corresponding Commitment object
    pub fn to_commitment(&self) -> Commitment {
        Commitment {
            x: self.commitment_value.clone(),
            p: self.parameters.0.clone(),
        }
    }
}

/// Return a suitable value for a to use in an opening
pub fn random_a(q: &Mpz) -> Mpz {
    // generate a - as a random integer mod q
    let seed_bytes = randombytes(8); // I trust libsodium more than gmp
    let mut seed = 0 as u64;
    for i in 0..8 {
        seed |= (seed_bytes[i] as u64) << (i*8);
    }

    let mut rand = rand::RandState::new();
    rand.seed_ui(seed);

    rand.urandom(q)
}

fn commit_add_data(c1: Commitment, c2: Commitment) -> Commitment {
    assert!(c1.p == c2.p); // not assert_eq because it wouldn't be helpful to print this all over the terminal
    Commitment {
        x: (c1.x * c2.x).modulus(&c1.p),
        p: c1.p.clone(),
    }
}

/// Naming of these operations refers to the data enclosed
impl Add<Commitment> for Commitment {
    type Output = Commitment;
    fn add(self, other: Commitment) -> Self::Output {
        commit_add_data(self, other)
    }
}

impl<'a> Add<&'a Commitment> for Commitment {
    type Output = Commitment;
    fn add(self, other: &'a Commitment) -> Self::Output {
        commit_add_data(self, other.clone())
    }
}

impl<'a> Add<Commitment> for &'a Commitment {
    type Output = Commitment;
    fn add(self, other: Commitment) -> Self::Output {
        commit_add_data(self.clone(), other)
    }
}

impl<'a, 'b> Add<&'a Commitment> for &'a Commitment {
    type Output = Commitment;
    fn add(self, other: &'a Commitment) -> Self::Output {
        commit_add_data(self.clone(), other.clone())
    }
}

fn commit_mul_data(c: Commitment, x: Mpz) -> Commitment {
    Commitment {
        x: c.x.powm(&x, &c.p),
        p: c.p.clone(),
    }
}

impl Mul<Mpz> for Commitment {
    type Output = Commitment;
    fn mul(self, other: Mpz) -> Self::Output {
        commit_mul_data(self, other)
    }
}

impl<'a> Mul<&'a Mpz> for Commitment {
    type Output = Commitment;
    fn mul(self, other: &'a Mpz) -> Self::Output {
        commit_mul_data(self, other.clone())
    }
}

impl<'a> Mul<Mpz> for &'a Commitment {
    type Output = Commitment;
    fn mul(self, other: Mpz) -> Self::Output {
        commit_mul_data(self.clone(), other)
    }
}

impl<'a, 'b> Mul<&'a Mpz> for &'a Commitment {
    type Output = Commitment;
    fn mul(self, other: &'a Mpz) -> Self::Output {
        commit_mul_data(self.clone(), other.clone())
    }
}

impl PartialEq for Commitment {
    fn eq(&self, other: &Commitment) -> bool {
        self.x == other.x
    }
}

impl Eq for Commitment {}

/// (p, q, g, h) where g and h are the bases suitable to be raised to a power forming the discrete logarithm problem, q is the subgroup in Z_p in which we will perform computations and p is the large prime which forms the large group. Calculations are done modulo p.
pub type DHParams = (Mpz, Mpz, Mpz, Mpz);

/// Writes DHParams to a file
pub fn write_dhparams<P: AsRef<Path>>(dhparams: &DHParams, path: P) -> io::Result<()> {
    let mut file = try!(fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .mode(0o600) // rw-------
        .open(path));

    let &(ref p, ref q, ref g, ref h) = dhparams;

    let _ = try!(file.write(&p.to_str_radix(16).into_bytes()));
    let _ = try!(file.write(b"\n"));
    let _ = try!(file.write(&q.to_str_radix(16).into_bytes()));
    let _ = try!(file.write(b"\n"));
    let _ = try!(file.write(&g.to_str_radix(16).into_bytes()));
    let _ = try!(file.write(b"\n"));
    let _ = try!(file.write(&h.to_str_radix(16).into_bytes()));

    Ok(())
}

/// Reads and validates DHParams from a file
pub fn read_dhparams<P: AsRef<Path>>(path: P) -> io::Result<DHParams> {
    let file = try!(fs::File::open(path));
    let mut reader = io::BufReader::new(file);

    let (mut p_str, mut q_str, mut g_str, mut h_str) = (String::new(), String::new(), String::new(), String::new());
    try!(reader.read_line(&mut p_str));
    try!(reader.read_line(&mut q_str));
    try!(reader.read_line(&mut g_str));
    try!(reader.read_line(&mut h_str));

    let p = match Mpz::from_str_radix(&p_str, 16) {
        Ok(x) => x,
        Err(_) => return Err(Error::new(ErrorKind::Other, "GMP Parse Error")),
    };
    let q = match Mpz::from_str_radix(&q_str, 16) {
        Ok(x) => x,
        Err(_) => return Err(Error::new(ErrorKind::Other, "GMP Parse Error")),
    };
    let g = match Mpz::from_str_radix(&g_str, 16) {
        Ok(x) => x,
        Err(_) => return Err(Error::new(ErrorKind::Other, "GMP Parse Error")),
    };
    let h = match Mpz::from_str_radix(&h_str, 16) {
        Ok(x) => x,
        Err(_) => return Err(Error::new(ErrorKind::Other, "GMP Parse Error")),
    };

    let params = (p, q, g, h);

    if !verify_dh_params(&params) {
        return Err(Error::new(ErrorKind::Other, "Read invalid parameter"));
    }
    
    Ok(params)
}

/// Verify a DHParameters instance
pub fn verify_dh_params(params: &DHParams) -> bool {
    let &(ref p, ref q, ref g, ref h) = params;

    verify_p(p) && verify_q(&q, &p) && verify_gh(&g, &q, &p) && verify_gh(&h, &q, &p)
}

// max value is 2^max_2exp. 
fn random_prime(min: &Mpz, max_2exp: u64) -> Option<Mpz> {
    if max_2exp <= (min.bit_length() as u64) {
        return None;
    }

    if min < &Mpz::from(2) {
        return None;
    }

    // seed gmp's random number generator
    let seed_bytes = randombytes(8);
    let mut seed = 0 as u64;
    for i in 0..8 {
        seed |= (seed_bytes[i] as u64) << (i*8);
    }
    let mut rand = rand::RandState::new();
    rand.seed_ui(seed);

    // keep trying random numbers until we get a prime
    let mut remaining_tries = 100 * max_2exp; // heuristic from "Cryptography Engineering" by Ferguson, Schnier and Kohno. Page 174.

    while remaining_tries > 0 {
        let n = rand.urandom_2exp(max_2exp);
        if n < *min {
            continue; // don't decrement the counter in this case because the heuristic I am using does not take this into account
        }
            
        if n.probab_prime_p(50) {
            return Some(n);
        }

        remaining_tries -= 1;
    }

    None
}

fn verify_q(q: &Mpz, p: &Mpz) -> bool {
    let mut q_min = Mpz::zero();
    q_min.setbit(255);
    if q < &q_min {
        return false;
    }
    
    let mut q_max = Mpz::zero();
    q_max.setbit(257);
    if q > &q_max {
        return false;
    }

    if !q.divides(&(p-1)) {
        return false;
    }

    if !q.probab_prime_p(50) {
        return false;
    }

    true
}

fn verify_p(p: &Mpz) -> bool {
    println!("ping");
    let mut p_min = Mpz::zero();
    p_min.setbit(2045);
    if p < &p_min {
        return false;
    }

    println!("p is big enough");

    let mut p_max = Mpz::zero();
    p_max.setbit(4097);
    if p > &p_max {
        return false;
    }

    println!(" p is small enough");

    if !p.probab_prime_p(50) {
        return false;
    }

    true
}

fn verify_gh(g: &Mpz, q: &Mpz, p: &Mpz) -> bool {
    if *g == Mpz::from(1) {
        return false;
    }

    if g.powm(&q, &p) != Mpz::from(1) {
        return false;
    }

    true
}

/// Generates diffie-hellman parameters appropriate for use with the commitments.
///
/// This will take a long time. The algorithm is the one presented on page 190 of "Cryptography Engineering" by Ferguson, Schneir and Kohono.
pub fn gen_dh_params() -> Result<DHParams, ()> {
    // seed gmp's random number generator
    let seed_bytes = randombytes(8); // I trust libsodium more than gmp
    let mut seed = 0 as u64;
    for i in 0..8 {
        seed |= (seed_bytes[i] as u64) << (i*8);
    }
    let mut rand = rand::RandState::new();
    rand.seed_ui(seed);

    loop {
        // choose q as a 256-bit prime
        let mut q_min = Mpz::zero();
        q_min.setbit(255);
        let rand_prime = random_prime(&q_min, 257);
        if rand_prime.is_none() {
            return Err(());
        }
        let q = rand_prime.unwrap();

        // Choose p as a large (2048-4096 bit) prime of the form n * q + 1
        for _ in 1..1000 {
            let n: Mpz;
            loop {
                let n_hopeful = rand.urandom_2exp(3840);
                let mut n_min = Mpz::zero();
                n_min.setbit(1792);

                if n_hopeful < n_min {
                    continue;
                }

                n = n_hopeful;
                break;
            }

            let p: Mpz = n.clone() * q.clone() + Mpz::from(1);
            if p.probab_prime_p(50) {
                // find g
                // choosing random alpha, set g =  alpha^n and check g is suitable
                loop {
                    let alpha = rand.urandom(&p);
                    let g = alpha.powm(&n, &p);

                    // check that g is suitable
                    if verify_gh(&g, &q, &p) {
                        // find h (same as g)
                        loop {
                            let alpha = rand.urandom(&p);
                            let h = alpha.powm(&n, &p);

                            // verify that h is suitable or continue looping
                            if verify_gh(&h, &q, &p) {
                                return Ok((p, q, g, h));
                            }
                        }
                    }
                }
            }
        }
    }
}

/*************** Tests ***************/
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_prime_test() {
        let p = random_prime(&Mpz::from(3), 3).unwrap();
        assert!(p.probab_prime_p(12));
        assert!(p > Mpz::from(2));
        assert!(p < Mpz::from(8));
    }

    #[test]
    #[ignore] // gen_dh_params() takes ages
    fn gen_dh_params_test() {
        let params = gen_dh_params().unwrap();
        assert!(verify_dh_params(&params));
    }

    #[test]
    #[ignore] // gen_dh_params() takes ages
    fn dh_params_file() {
        let dh_params = gen_dh_params().unwrap();
        let path = "./dh_params_file_test_deleteme.txt";
        write_dhparams(&dh_params, path).unwrap();
        let read_dh_params = read_dhparams(path).unwrap();
        let _ = fs::remove_file(path);
        assert!(read_dh_params == dh_params);
    }
}
