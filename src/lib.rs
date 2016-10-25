//! project-crypto
//! 
//! This library contains the cryptography used in my third year project at university.
//! Please do not use this for anything important. This cryptography has not been reveiwed. 
//! This project is licenced under GPL-3 or (at your option) any later version of the GPL as published by the [free software foundation](https://fsf.org)

extern crate sodiumoxide;

mod symmetric;

mod asymmetric;

#[cfg(test)]
mod tests { // todo
    #[test]
    fn it_works() {
    }
}
