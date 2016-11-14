initSidebarItems({"constant":[["AUTH_TAG_BYTES","Length of an authentication tag, so that users don't have to use ...::auth::hmacsha512256"]],"struct":[["Digest","A wrapper around sha256::Digest so that we can implement Drop on it to clean up the memory when it goes out of scope. This is necessary because often our shared secret keys are sha256 digests."],["State","Stores the state of the symmetric encryption system. Memory is zeroed when this goes out of scope"]]});