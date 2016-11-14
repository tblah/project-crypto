# project-crypto
Cryptographic protocol written as part of my third year project at university.

This project is licenced under GPL version 3 or later as published by the [Free Software Foundation](https://fsf.org)

**Please do not use this for anything important. It has not been reviewed by a professional**

[The documentation generated by cargo-doc](https://tblah.github.io/project-crypto/)

Building (you may need to install libsodium):
```
cargo build
```

Testing:
```
cargo test
```

To generate your own documentation:

```
cargo doc 
```

The main gotcha is to remember to call [sodiumoxide::init](https://dnaq.github.io/sodiumoxide/sodiumoxide/fn.init.html).

For a description of the cryptographic design and for usage examples, see the cargo documentation. 
