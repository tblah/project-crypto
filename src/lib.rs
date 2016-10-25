//! project-crypto
//! 
//! This library contains the cryptography used in my third year project at university.
//! Please do not use this for anything important. This cryptography has not been reveiwed. 
//! This project is licenced under GPL-3 or (at your option) any later version of the GPL as published by the [free software foundation](https://fsf.org)

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

extern crate sodiumoxide;

mod symmetric;

mod asymmetric;

#[cfg(test)]
mod tests { // todo
    #[test]
    fn it_works() {
    }
}
