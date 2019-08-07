# Minimal Cipher _(minimal-cipher)_

> Minimal encryption/decryption [JWE](https://tools.ietf.org/html/rfc7516)/[CWE](https://tools.ietf.org/html/rfc8152) library, secure algs only, browser-compatible

## Table of Contents

- [Security](#security)
- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [Commercial Support](#commercial-support)
- [License](#license)

## Security

TBD

## Background

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
incompatible with the current requirements for a 
[JWE (JOSE Web Encryption)](https://tools.ietf.org/html/rfc7516)
`protected` clear text header.

This library's API requires an interface for Key Encryption Key (KEKs). This
enables key material that is protected from exfiltration to be used via HSM/SSM
APIs, including Web KMS (TODO: citation needed).

## Install

- Node.js 8.3+ required.

To install locally (for development):

```
git clone https://github.com/digitalbazaar/minimal-cipher.git
cd minimal-cipher
npm install
```

## Usage

Pick a Cipher interface (`recommended` or `fips`) and create an instance:

```js
const {Cipher} = require('minimal-cipher');

const cipher = new Cipher(); // by default {version='recommended'}
```

### Encrypting

To encrypt something (to create a cipher, serialized as a JWE JSON document), 
you will need:

* Some data to encrypt (a string, an object, a stream)
* Keys (called Key Agreement Keys, or KAKs for short)

(You'll also need a `keyResolver`, more about that later.)

First, assemble your Key Agreement public keys (you'll be encrypting with them, 
and the intended recipient will use the corresponding private keys to decrypt).

Put together a list of `recipients` (essentially, you're listing which keys
are intended to decrypt the message):

```js
// Retrieve them from config or from a ledger
const keyAgreementKey = await fetchFromSomewhere();

// or derive them from an Ed25519 signing key
const X25519KeyPair = require('x25519-key-pair');
const {Ed25519KeyPair} = require('crypto-ld');
const edKeyPair = await Ed25519KeyPair.generate();
const keyAgreementKey = X25519KeyPair.fromEdKeyPair(edKeyPair);
// Don't forget to set your key's id. For example, DID + fingerprint
keyAgreementKey.id = `${did}#${keyAgreementKey.fingerprint()}`;

const recipient = {
  header: {
    kid: keyAgreementKey.id,
    alg: 'ECDH-ES+A256KW'
  }
}

const recipients = [recipient];
```

Create the `keyResolver`:

```js
// TODO: Explain this part
```

Create the JWE:

```js
// To encrypt a string or a Uint8Array
const data = 'plain text';
const jweDoc = await cipher.encrypt({data, recipients, keyResolver});

// To encrypt an object
const obj = { key: 'value' };
const jweDoc = await cipher.encryptObject({obj, recipients, keyResolver});
```

TODO: Describe the required KEK API:
// `id`, `algorithm`, `wrapKey({unwrappedKey})`, and `unwrakKey({wrappedKey})`

## Contribute

See [the contribute file](https://github.com/digitalbazaar/bedrock/blob/master/CONTRIBUTING.md)!

PRs accepted.

Small note: If editing the README, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## Commercial Support

Commercial support for this library is available upon request from
Digital Bazaar: support@digitalbazaar.com

## License

[New BSD License (3-clause)](LICENSE) © Digital Bazaar
