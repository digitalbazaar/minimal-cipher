// `C20P` encrypted legacy JWE; backwards compatible support for decrypting
// this is in this library (but cannot encrypt using it)
export const LEGACY_JWE = {
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

export const LEGACY_KEY_PAIR = {
  privateKeyBase58: 'DqBNP7KkbiTJbXAA6AmfTjhQU3cMeQwtDBeM8Z92duz1',
  publicKeyBase58: 'C5URuM3ttmRa2s7BtcBUv2688Z23prZBX5qyQWNnn9UJ'
};

export const key1Data = {
  id: 'did:key:z6MkwLz9d2sa3FJjni9A7rXmicf9NN3e5xgJPUmdqaFMTgoE#' +
    'z6LSmgLugoC8vUoK1ouCTGKdqFdpg5jb3H193L6wFJucX14U',
  controller: 'did:key:z6MkwLz9d2sa3FJjni9A7rXmicf9NN3e5xgJPUmdqaFMTgoE',
  type: 'X25519KeyAgreementKey2020',
  publicKeyMultibase: 'z6LSmgLugoC8vUoK1ouCTGKdqFdpg5jb3H193L6wFJucX14U',
  privateKeyMultibase: 'z3wedGgRfySXFenmev8caU3eqBeDXrzDsdi21ofMZN8s8Exm'
};

export const key2Data = {
  id: 'did:key:z6MkttYcTAeZbVsBiAmxFj2LNSgNzj5gAdb3hbE4QwmFTK4Z#z6LSjPQz1GAR' +
  'HBL7vnMW8XiH3UYVkgETpyk8oKhXeeFRGpQh',
  controller: 'did:key:z6MkttYcTAeZbVsBiAmxFj2LNSgNzj5gAdb3hbE4QwmFTK4Z',
  type: 'X25519KeyAgreementKey2020',
  publicKeyMultibase: 'z6LSjPQz1GARHBL7vnMW8XiH3UYVkgETpyk8oKhXeeFRGpQh',
  privateKeyMultibase: 'z3web9AUP49zFCBVEdQ4ksbSmzgi6JqNCA84XNxUAcMDZgZc'
};

export const fipsKey1Data = {
  '@context': 'https://w3id.org/security/multikey/v1',
  id: 'did:key:zDnaey9HdsvnNjAn2PaCXXJihjNsiXWzCvRS9HgEbcjPqvPNY#' +
    'zDnaey9HdsvnNjAn2PaCXXJihjNsiXWzCvRS9HgEbcjPqvPNY',
  type: 'Multikey',
  controller: 'did:key:zDnaey9HdsvnNjAn2PaCXXJihjNsiXWzCvRS9HgEbcjPqvPNY',
  publicKeyMultibase: 'zDnaey9HdsvnNjAn2PaCXXJihjNsiXWzCvRS9HgEbcjPqvPNY',
  secretKeyMultibase: 'z42tqAhAsKYYJ3RnqzYKMzFvExVNK3NPNHgRHihqJjDAUzx6'
};

export const fipsKey2Data = {
  '@context': 'https://w3id.org/security/multikey/v1',
  id: 'did:key:zDnaeX3DFUeCwF6dvvXnewsLtumrDFRu8bquxi96FZ6A5dd7b#' +
    'zDnaeX3DFUeCwF6dvvXnewsLtumrDFRu8bquxi96FZ6A5dd7b',
  type: 'Multikey',
  controller: 'did:key:zDnaeX3DFUeCwF6dvvXnewsLtumrDFRu8bquxi96FZ6A5dd7b',
  publicKeyMultibase: 'zDnaeX3DFUeCwF6dvvXnewsLtumrDFRu8bquxi96FZ6A5dd7b',
  secretKeyMultibase: 'z42tvVHmQwRcjKNBxig4kbDRuVyM2uhGxVJAgUcxtQ41YwbP'
};
