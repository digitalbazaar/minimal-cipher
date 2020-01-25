# minimal-cipher ChangeLog

### Changed
- Update dependencies.

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
