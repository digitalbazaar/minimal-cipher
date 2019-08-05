/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
const chai = require('chai');
const {Cipher} = require('../../');
const {TextDecoder, ReadableStream} = require('../../util');
const KaK = require('../KaK');
const chaiCipher = require('../chai-cipher');

chai.should();
chai.use(chaiCipher);

const cipherAlgorithms = ['recommended', 'fips'];

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

      async function encryptStream({data}) {
        const stream = new ReadableStream({
          pull(controller) {
            controller.enqueue(data);
            controller.close();
          }
        });
        const encryptStream = await cipher.createEncryptStream(
          {recipients, keyResolver, chunkSize: 1});
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
        const decryptStream = await cipher.createDecryptStream(
          {keyAgreementKey});
        const writer = decryptStream.writable.getWriter();
        for(const chunk of chunks) {
          writer.write(chunk);
        }
        writer.close();
        const reader = decryptStream.readable.getReader();
        const data = [];
        let value;
        let done = false;
        while(!done) {
          try {
            ({value, done} = await reader.read());
            if(!done) {
              data.push(value);
            }
          } catch(e) {
            console.error(e);
            throw e;
          }
        }
        // FIXME Buffer is not in browser
        // this works fine however in all tests.
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
    });
  });
});
