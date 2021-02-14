// `C20P` encrypted legacy JWE; backwards compatible support for decrypting
// this is in this library (but cannot encrypt using it)
exports.LEGACY_JWE = {
  protected: 'eyJlbmMiOiJBMjU2R0NNIn0',
  recipients: [
    {
      header: {
        kid: 'urn:123',
        alg: 'ECDH-ES+A256KW',
        epk: {
          kty: 'OKP',
          crv: 'X25519',
          x: 'TxnCS0ZP0g0IR9jQ1y4BDfFMfYvuzTPJiD5yhWnZxhQ'
        },
        apu: 'TxnCS0ZP0g0IR9jQ1y4BDfFMfYvuzTPJiD5yhWnZxhQ',
        apv: 'dXJuOjEyMw'
      },
      encrypted_key: 'HxDN7bJzsbhjQfsX_erWvK-_vc7BM2zpOTvs3a_5aoIMgm0HW65cFQ'
    }
  ],
  iv: '1CwAoB6bs1HPh6No',
  ciphertext: 'iKaHhDdbGFmgkUgU5D0W',
  tag: 'eIzP_YhcLSuX-qJANN7M7A'
};

exports.LEGACY_KEY_PAIR = {
  privateKeyBase58: 'DqBNP7KkbiTJbXAA6AmfTjhQU3cMeQwtDBeM8Z92duz1',
  publicKeyBase58: 'C5URuM3ttmRa2s7BtcBUv2688Z23prZBX5qyQWNnn9UJ'
};

