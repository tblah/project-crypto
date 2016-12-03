//! Asymmetric encryption module.
//! 
//! self::key_exchange is re-exported for backwards compatibility. See that module for it's tests and documentation.
//!
//! Unfortunately key_exchange and sign have to use a different representation of the keypair because libsodium uses incompatible representations of the public key between signatures and key exchanges (public interface to curve25519_mult_base).

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

pub mod key_exchange;
//pub mod sign;





