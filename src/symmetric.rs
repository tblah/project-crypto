//! symmetric.rs
//! 
//! This module will provide an interface for symmetric (secret key) cryptography as implemented in my project.
//! This project is licenced under GPL version 3 or (at your choice) any later version of the GPL published by the [Free Software Foundation](https://fsf.org)
//! 
//! The cryptography uses the secret key interface in [libsodium](https://libsodium.org). Ratcheting is used to provide some forward secrecy by deriving a different key for each message from the shared secret. To acheive this, the key for message N by hashing the shared key N times. A similar ratchet is used in Signal. 


