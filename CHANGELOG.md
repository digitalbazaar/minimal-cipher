# minimal-cipher ChangeLog

## 3.0.0 - 2021-04-TBD

### Changed
- **BREAKING**: Update KEY_TYPE to `X25519KeyAgreementKey2020`.

## 2.0.0 - 2021-03-12

### Changed
- **BREAKING**: Changed README instructions to use
  [`x25519-key-agreement-key-2019 v4+`](https://github.com/digitalbazaar/x25519-key-agreement-key-2019)
  key type examples, which itself is based on `crypto-ld v4+`.
  See also [`x25519-key-agreement-key-2019 v4+` Changelog](https://github.com/digitalbazaar/x25519-key-agreement-key-2019/blob/master/CHANGELOG.md#400---2021-03-11),
  [`crypto-ld` v4.0 Changelog](https://github.com/digitalbazaar/crypto-ld/blob/master/CHANGELOG.md#400---2020-08-01)
- Update `@stablelib/chacha20poly1305` and `@stablelib/xchacha20poly1305` deps
  to their latest 1.0 versions. (Should be no breaking changes there.)
- Update `web-streams-polyfill` to major version `v3.0.0`
  (see [its changelog entry](https://github.com/MattiasBuelens/web-streams-polyfill/blob/master/CHANGELOG.md#v300-2020-07-20)).
  (Should be no changes that affect this lib.)

### Purpose and Upgrade Instructions
There no API changes to `minimal-cipher` itself (aside from the rename of its
npm package to `@digitalbazaar/minimal-cipher`), so upgrading from `1.4.x` to
`2.0.0` only involves making sure that the keys being used for key agreement
are generated using the newer `crypto-ld` v4 method (see `minimal-cipher` README
for examples).

## 1.4.1 - 2021-03-11
### Changed
- JSDOC comments in `Cipher.js`.
- Upgraded eslint to ^7.0.0.
- Upgraded eslint-plugin-jsdoc to ^37.0.0.
- Refactored creating recipients.

### Fixed
- decrypt helper function in test suite to be able to handle multiple chunks.

### Added
- new helper function createUnencryptedStream in test suite.
- better jsdoc comments to help clarify test suite functions.
- chunkSize tests for decrypt.

## 1.4.0 - 2020-08-20

### Changed
- Use Node.js `crypto.diffieHellman` for computing DH secret when available.

## 1.3.0 - 2020-03-18

### Added
- Add validation of parameters in DecryptTransformer constructor.

## 1.2.0 - 2020-01-28

### Changed
- Update dependencies.
- Use base58-universal.

## 1.1.0 - 2019-12-17

### Added
- Use XChaCha20Poly1305 (instead of ChaCha20Poly1305) for the
  recommended encryption algorithm. Backwards compatibility support
  for decrypting ChaCha20Poly1305 is provided, but encryption will
  now *only* use XChaCha20Poly1305.

## 1.0.1 - 2019-08-02

### Fixed
- Ensure exported key is wrapped in a Uint8Array.

## 1.0.0 - 2019-08-02

## 0.1.0 - 2019-08-02

### Added
- Add core files.

- See git history for changes previous to this release.
