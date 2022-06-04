# minimal-cipher ChangeLog

## 5.0.0 - 2022-xx-xx

### Changed
- **BREAKING**: Convert to module (ESM).
- **BREAKING**: Require Node.js >=14.
- **BREAKING**: Use `globalThis` for browser crypto and streams.
- **BREAKING**: Require WebCrypto. Older browsers and Node.js 14 users need to
  install an appropriate polyfill.
- **BREAKING**: Require WebStreams. Older browsers and Node.js <18 users need to
  install an appropriate polyfill.
- Update dependencies.
- Lint module.

## 4.0.2 - 2021-09-17

### Fixed
- Fix parameters passed to key wrap/unwrapping functions in aeskw.js. The key
  usage param for the key to be wrapped/unwrapped was inconsistent and not
  accepted on certain browsers (Firefox). A previous commit conflated the key
  usage field for the key to be wrapped with the key wrapping key itself and
  this has been corrected and commented to help avoid future problems.

## 4.0.1 - 2021-08-18

### Fixed
- Pin web-streams-polyfill@3.0.x. This has been done because version 3.1+ of the
  polyfill have added checks to force the same version of the polyfill to be used
  across all code that uses the ReadableStream API. This means that the polyfill
  does not just polyfill an interface such that it is compatible with other
  libraries; those libraries must all know about each other and use the exact
  same implementation. Hopefully, this will be fixed in a later version of the
  polyfill.

## 4.0.0 - 2021-07-22

### Changed
- **BREAKING**: Upgrade to `@digitalbazaar/x25519-verification-key-2020` v2.0,
  which changes the key serialization format to multicodec (in addition to multibase).

## 3.0.0 - 2021-04-01

### Changed
- **BREAKING**: Update `KEY_TYPE` to `X25519KeyAgreementKey2020`.

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
