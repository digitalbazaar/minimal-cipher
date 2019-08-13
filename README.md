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

const cipher = new Cipher(); // by default {version: 'recommended'}
```

### Encrypting

To encrypt something (to create a cipher, serialized as a JWE JSON document), 
you will need:

* Some data to encrypt (a string, an object, a stream)
* Keys (called Key Agreement Keys, or KAKs for short)

(You'll also need a `keyResolver`, more about that later.)

First, assemble your Key Agreement public keys (you'll be encrypting with them, 
and the intended recipient will use the corresponding private keys to decrypt).

Put together a list of `recipients` (essentially, you're listing the `id`s of
public/private key pairs that will be used to encrypt/decrypt the message):

```js
// Retrieve them from config, a ledger, registry or back channel
const keyAgreementKey = await fetchFromSomewhere();

// or derive them from an existing Ed25519 signing key
const X25519KeyPair = require('x25519-key-pair');
const {Ed25519KeyPair} = require('crypto-ld');
const edKeyPair = await Ed25519KeyPair.generate();
const keyAgreementKey = X25519KeyPair.fromEdKeyPair(edKeyPair);
// Don't forget to set your key's id. For example, DID + fingerprint
keyAgreementKey.id = `${did}#${keyAgreementKey.fingerprint()}`;

// or derive them from an authentication key extracted from DID Document 
const didDoc = await veresDriver.get({did});
const authnKey = didDoc.getVerificationMethod({proofPurpose: 'authentication'});
const edKeyPair = await Ed25519KeyPair.from(authnKey);
const keyAgreementKey = X25519KeyPair.fromEdKeyPair(edKeyPair);
keyAgreementKey.id = authnKey.id;

const recipient = {
  header: {
    kid: keyAgreementKey.id,
    alg: 'ECDH-ES+A256KW'
  }
}

const recipients = [recipient];
```

You'll also need a `keyResolver`. Notice that `recipients` lists only key IDs,
not the keys themselves. A `keyResolver` is a function that accepts a key ID
and resolves to the public key corresponding to it.

Some example resolvers:

```js
// Basic hardcoded key resolver; you already have the key material
const publicKeyNode = {
  '@context': 'https://w3id.org/security/v2',
  id: keyAgreementKey.id,
  type: 'X25519KeyAgreementKey2019',
  publicKeyBase58: keyAgreementKey.publicKeyBase58
};
const keyResolver = async () => publicKeyNode; 
```

```js
// A more advanced resolver based on DID doc authentication keys
const keyResolver = async ({id}) => {
  // Use veres driver to fetch the authn key directly
  const authKeyPair = await Ed25519KeyPair.from(await veresDriver.get({did: keyId}));
  // Convert authn key to key agreement key
  return X25519KeyPair.fromEdKeyPair(authKeyPair);
}
```

```js
// Using did-veres-one driver as a resolver for did:v1:nym: DID keys
// TODO: Implement this
```

```js
// Using the did:key method driver as a key resolver
```

Create the JWE:

```js
// To encrypt a string or a Uint8Array
const data = 'plain text';
const jweDoc = await cipher.encrypt({data, recipients, keyResolver});

// To encrypt an object
const obj = {key: 'value'};
const jweDoc = await cipher.encryptObject({obj, recipients, keyResolver});
```

### Decrypting

Decrypt a JWE JSON Document, using a private `keyAgreementKey`:

```js
const data = await cipher.decrypt({jwe, keyAgreementKey});

const object = await cipher.decryptObject({jwe, keyAgreementKey});
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
