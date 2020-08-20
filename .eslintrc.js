module.exports = {
  root: true,
  extends: [
    'eslint-config-digitalbazaar',
    'eslint-config-digitalbazaar/jsdoc'
  ],
  env: {
    node: true
  },
  globals: {
    CryptoKey: true,
    TextDecoder: true,
    TextEncoder: true,
    Uint8Array: true
  }
}
