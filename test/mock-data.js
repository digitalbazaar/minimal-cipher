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

exports.key1Data = {
  id: 'did:key:z6MkuBLrjSGt1PPADAvuv6rmvj4FfSAfffJotC6K8ZEorYmv#z6LSe' +
  'RSE5Em5oJpwdk3NBaLVERBS332ULC7EQq5EtMsmXhsM',
  controller: 'did:key:z6MkuBLrjSGt1PPADAvuv6rmvj4FfSAfffJotC6K8ZEorYmv',
  type: 'X25519KeyAgreementKey2020',
  publicKeyMultibase: 'z6LSeRSE5Em5oJpwdk3NBaLVERBS332ULC7EQq5EtMsmXhsM',
  privateKeyMultibase: 'z3weeMD56C1T347EmB6kYNS7trpQwjvtQCpCYRpqGz6mcemT'
};

exports.key2Data = {
  id: 'did:key:z6MkttYcTAeZbVsBiAmxFj2LNSgNzj5gAdb3hbE4QwmFTK4Z#z6LSjPQz1GAR' +
  'HBL7vnMW8XiH3UYVkgETpyk8oKhXeeFRGpQh',
  controller: 'did:key:z6MkttYcTAeZbVsBiAmxFj2LNSgNzj5gAdb3hbE4QwmFTK4Z',
  type: 'X25519KeyAgreementKey2020',
  publicKeyMultibase: 'z6LSjPQz1GARHBL7vnMW8XiH3UYVkgETpyk8oKhXeeFRGpQh',
  privateKeyMultibase: 'z3web9AUP49zFCBVEdQ4ksbSmzgi6JqNCA84XNxUAcMDZgZc'
};
