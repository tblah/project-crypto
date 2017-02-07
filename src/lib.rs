//! # Proj_crypto library crate.
//! 
//! This library contains the cryptography used in my third year project at university.
//! **Please do not use this for anything important. This cryptography has not been reviewed.**
//!
//! See the code example in the asymmetric module for a brief overview of what this library can do.
//!
//! This project is licenced under the terms of the GNU General Public Licence as published by the Free Software Foundation, either version 3 of the licence, or (at your option) any later version.

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

#![crate_name = "proj_crypto"]
#![crate_type = "lib"]
#![warn(missing_docs)]
#![warn(non_upper_case_globals)]
#![warn(non_camel_case_types)]
#![warn(unused_qualifications)]

extern crate sodiumoxide;
extern crate gmp;

pub mod symmetric;
pub mod asymmetric;
