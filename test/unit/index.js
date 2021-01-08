/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const chai = require('chai');
const {Cipher} = require('../../');
const {TextDecoder, ReadableStream} = require('../../util');
const KaK = require('../KaK');
const chaiCipher = require('../chai-cipher');

chai.should();
chai.use(chaiCipher);

const cipherAlgorithms = ['recommended', 'fips'];

// `C20P` encrypted legacy JWE; backwards compatible support for decrypting
// this is in this library (but cannot encrypt using it)
const LEGACY_JWE = {
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

const LEGACY_KEY_PAIR = {
  privateKeyBase58: 'DqBNP7KkbiTJbXAA6AmfTjhQU3cMeQwtDBeM8Z92duz1',
  publicKeyBase58: 'C5URuM3ttmRa2s7BtcBUv2688Z23prZBX5qyQWNnn9UJ'
};

describe('minimal-cipher', function() {
  cipherAlgorithms.forEach(algorithm => {
    describe(`${algorithm} algorithm`, function() {

      // each test inits data to null
      let cipher, keyAgreementKey, publicKeyNode, recipients = null;

      // keyResolver returns publicKeyNode
      const keyResolver = async () => publicKeyNode;

      beforeEach(async function() {
        cipher = new Cipher({version: algorithm});
        keyAgreementKey = new KaK();
        publicKeyNode = {
          '@context': 'https://w3id.org/security/v2',
          id: keyAgreementKey.id,
          type: keyAgreementKey.type,
          publicKeyBase58: keyAgreementKey.publicKeyBase58
        };
        recipients = [{
          header: {kid: keyAgreementKey.id, alg: 'ECDH-ES+A256KW'}
        }];
      });

      function getRandomUint8({size = 50} = {}) {
        return new Uint8Array(size).map(
          () => Math.floor(Math.random() * 255));
      }

      async function encryptStream({data, chunkSize = 5}) {
        const stream = new ReadableStream({
          pull(controller) {
            for(let i = 0; i < data.length; i += chunkSize) {
              const chunk = data.slice(i, i + chunkSize);
              controller.enqueue(chunk);
            }
            controller.close();
          }
        });
        const encryptStream = await cipher.createEncryptStream(
          {recipients, keyResolver, chunkSize});
        const readable = stream.pipeThrough(encryptStream);
        const reader = readable.getReader();
        const chunks = [];
        let value;
        let done = false;
        while(!done) {
          try {
            ({value, done} = await reader.read());
            if(!done) {
              chunks.push(value);
            }
          } catch(e) {
            console.error(e);
            throw e;
          }
        }
        return chunks;
      }

      async function decryptStream({chunks}) {
        const stream = new ReadableStream({
          pull(controller) {
            chunks.forEach(c => controller.enqueue(c));
            controller.close();
          }
        });
        const decryptStream = await cipher.createDecryptStream(
          {keyAgreementKey});
        const readable = stream.pipeThrough(decryptStream);
        const reader = readable.getReader();
        let data = new Uint8Array(0);
        let value;
        let done = false;
        while(!done) {
          try {
            ({value, done} = await reader.read());
            if(!done) {
              // create a new array with the new length
              const next = new Uint8Array(data.length + value.length);
              // set the first values to the existing chunk
              next.set(data);
              // set the chunk's values to the rest of the array
              next.set(value, data.length);
              // update the streamData
              data = next;
            }
          } catch(e) {
            console.error(e);
            throw e;
          }
        }
        return Uint8Array.from(data);
      }

      it('should encrypt a simple Uint8Array', async function() {
        const data = getRandomUint8();
        const result = await cipher.encrypt({data, recipients, keyResolver});
        result.should.be.a.JWE;
      });

      it('should encrypt a simple string', async function() {
        const data = 'simple';
        const result = await cipher.encrypt({data, recipients, keyResolver});
        result.should.be.a.JWE;
      });

      it('should encrypt a simple object', async function() {
        const obj = {simple: true};
        const result = await cipher.encryptObject(
          {obj, recipients, keyResolver});
        result.should.be.a.JWE;
      });

      it('should encrypt a stream', async function() {
        const data = getRandomUint8();
        const chunks = await encryptStream({data});
        chunks.length.should.be.gte(0);
        for(const chunk of chunks) {
          chunk.jwe.should.be.a.JWE;
        }
      });

      it('should decrypt an Uint8Array', async function() {
        const data = getRandomUint8();
        const jwe = await cipher.encrypt({data, recipients, keyResolver});
        jwe.should.be.a.JWE;
        const result = await cipher.decrypt({jwe, keyAgreementKey});
        result.should.deep.equal(data);
      });

      it('should decrypt a simple string', async function() {
        const data = 'simple';
        const jwe = await cipher.encrypt({data, recipients, keyResolver});
        jwe.should.be.a.JWE;
        const result = await cipher.decrypt({jwe, keyAgreementKey});
        const resultString = new TextDecoder().decode(result);
        resultString.should.deep.equal(data);
      });

      it('should decrypt a simple object', async function() {
        const obj = {simple: true};
        const jwe = await cipher.encryptObject(
          {obj, recipients, keyResolver});
        jwe.should.be.a.JWE;
        const result = await cipher.decryptObject({jwe, keyAgreementKey});
        result.should.deep.equal(obj);
      });

      it('should decrypt a stream', async function() {
        const data = getRandomUint8();
        const chunks = await encryptStream({data});
        chunks.length.should.be.gte(0);
        for(const chunk of chunks) {
          chunk.jwe.should.be.a.JWE;
        }
        const result = await decryptStream({chunks});
        result.length.should.be.gte(0);
        result.should.deep.eql(data);
      });

      it('should decrypt a legacy-encrypted simple object', async function() {
        // decrypts `C20P` JWE (now replaced by `XC20P`)
        const jwe = LEGACY_JWE;
        keyAgreementKey = new KaK({keyPair: LEGACY_KEY_PAIR});
        publicKeyNode = {
          '@context': 'https://w3id.org/security/v2',
          id: keyAgreementKey.id,
          type: keyAgreementKey.type,
          publicKeyBase58: keyAgreementKey.publicKeyBase58
        };
        const obj = {simple: true};
        jwe.should.be.a.JWE;
        const result = await cipher.decryptObject({jwe, keyAgreementKey});
        result.should.deep.equal(obj);
      });
    });
  });
});
