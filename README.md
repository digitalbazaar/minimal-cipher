# minimal-cipher
Minimal encryption/decryption JWE/CWE library, secure algs only,
browser-compatible.

Every version of this library will only offer at most two algorithms
for encryption/decryption: a recommended algorithm and a FIPS-compliant
algorithm. The encryption API will expect the user to specify "recommended"
or "fips" as the version of the algorithm to use, defaulting to "recommended".

In the event that the FIPS-compliant algorithm is the same as the recommended
one in a given version of this library, then that particular version will
use the same algorithm regardless of the user specified "version".

This version of the library will use "ChaCha20-Poly1305" as the "recommended"
version and 256-bit "AES-GCM" as the FIPS-compliant version. A future version
of this library that uses "XChaCha20-Poly1305" as the "recommended" version
will be released when a browser-compatible implementation becomes available.

Note: XSalsa20-Poly1305 is an AE (Authenticated Encryption) algorithm, not
an AEAD (Authenticated Encryption and Associated Data) algorithm, making it
incompatible with the current requirements for a JWE (JOSE Web Encryption)
`protected` clear text header.

This library's API requires an interface for Key Encryption Key (KEKs). This
enable key material that is protected from exfiltration to be used via HSM/SSM
APIs, including Web KMS (TODO: citation needed).

TODO: Describe the required KEK API:
// `id`, `algorithm`, `wrapKey({unwrappedKey})`, and `unwrakKey({wrappedKey})`
