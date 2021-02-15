/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const chai = require('chai');
const {Cipher} = require('../../');
const {TextDecoder, ReadableStream} = require('../../util');
const KaK = require('../KaK');
const chaiCipher = require('../chai-cipher');
const {store} = require('../store');
const {LEGACY_JWE, LEGACY_KEY_PAIR} = require('../mock-data');

chai.should();
chai.use(chaiCipher);

const cipherAlgorithms = ['recommended', 'fips'];

describe('minimal-cipher', function() {
  cipherAlgorithms.forEach(algorithm => {
    describe(`${algorithm} algorithm`, function() {

      // each test inits data to null
      let cipher, keyAgreementKey, recipient = null;

      // keyResolver returns publicKeyNode
      const keyResolver = async ({id}) => store.get(id);

      beforeEach(async function() {
        cipher = new Cipher({version: algorithm});
        keyAgreementKey = new KaK({id: 'urn:123'});
        recipient = [{
          header: {kid: keyAgreementKey.id, alg: 'ECDH-ES+A256KW'}
        }];
      });

      function getRandomUint8({size = 50} = {}) {
        return new Uint8Array(size).map(
          () => Math.floor(Math.random() * 255));
      }
      /**
       * Creates a new unencrypted ReadableStream.
       * This should act similar to a file stream in a browser.
       *
       * @param {object} options - Options to use.
       * @param {Uint8Array} options.data - The data being streamed.
       * @param {number} [options.queueSize = 5] - Determines how the data is
       *   sliced and how many chunks are enqueued in the stream.
       *
       * @returns {ReadableStream} Returns a ReadableStream.
       */
      const createUnencryptedStream = ({data, queueSize = 5}) => {
        return new ReadableStream({
          pull(controller) {
            // break the unit8Array into chunks using queueSize
            for(let i = 0; i < data.length; i += queueSize) {
              const chunk = data.slice(i, i + queueSize);
              controller.enqueue(chunk);
            }
            controller.close();
          }
        });
      };
      /**
       * Creates an encrypted stream from an unencrypted ReadableStream.
       *
       * @param {object} options - Options to use.
       * @param {Uint8Array} options.data - The data for the stream.
       * @param {number} [options.queueSize = 5] - How many chunks the
       *   unencrypted stream should contain.
       * @param {number} [options.chunkSize = 5] - The size of the chunks in the
       *   encrypted stream.
       * @param {Array<object>} [options.recipients=recipient] - A list of JWE
       *   recipients.
       *
       * @returns {Promise<Array>} The resulting encrypted chunks.
       */
      async function encryptStream({
        data,
        queueSize = 5,
        chunkSize = 5,
        recipients = recipient
      }) {
        const unencryptedStream = createUnencryptedStream({data, queueSize});
        const encryptStream = await cipher.createEncryptStream(
          {recipients, keyResolver, chunkSize});
        const readable = unencryptedStream.pipeThrough(encryptStream);
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

      /**
       * Takes in encrypted chunks and returns an unencrypted Uint8Array.
       *
       * @param {object} options - Options to use.
       * @param {Array} options.chunks - An array of encrypted data.
       *
       * @returns {Promise<Uint8Array>} The unencrypted data.
       */
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
        const result = await cipher.encrypt({data, recipients: recipient, keyResolver});
        result.should.be.a.JWE;
      });

      it('should encrypt a simple string', async function() {
        const data = 'simple';
        const result = await cipher.encrypt({data, recipients: recipient, keyResolver});
        result.should.be.a.JWE;
      });

      it('should encrypt a simple object', async function() {
        const obj = {simple: true};
        const result = await cipher.encryptObject(
          {obj, recipients: recipient, keyResolver});
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
        const jwe = await cipher.encrypt({data, recipients: recipient, keyResolver});
        jwe.should.be.a.JWE;
        const result = await cipher.decrypt({jwe, keyAgreementKey});
        result.should.eql(data);
      });

      it('should decrypt a simple string', async function() {
        const data = 'simple';
        const jwe = await cipher.encrypt({data, recipients: recipient, keyResolver});
        jwe.should.be.a.JWE;
        const result = await cipher.decrypt({jwe, keyAgreementKey});
        const resultString = new TextDecoder().decode(result);
        resultString.should.eql(data);
      });

      it('should decrypt a simple object', async function() {
        const obj = {simple: true};
        const jwe = await cipher.encryptObject(
          {obj, recipients: recipient, keyResolver});
        jwe.should.be.a.JWE;
        const result = await cipher.decryptObject({jwe, keyAgreementKey});
        result.should.eql(obj);
      });

      it('should decrypt a stream with chunkSize 1 byte', async function() {
        const data = getRandomUint8({size: 100});
        const chunks = await encryptStream({data, chunkSize: 1});
        chunks.length.should.eql(100);
        for(const chunk of chunks) {
          chunk.jwe.should.be.a.JWE;
        }
        const result = await decryptStream({chunks});
        result.length.should.eql(data.length);
        result.should.deep.eql(data);
      });

      it('should decrypt a stream with chunkSize 5 bytes', async function() {
        const data = getRandomUint8({size: 100});
        const chunks = await encryptStream({data, chunkSize: 5});
        chunks.length.should.eql(20);
        for(const chunk of chunks) {
          chunk.jwe.should.be.a.JWE;
        }
        const result = await decryptStream({chunks});
        result.length.should.eql(data.length);
        result.should.deep.eql(data);
      });

      it('should decrypt a stream with chunkSize 1 megabyte', async function() {
        const data = getRandomUint8({size: 100});
        const chunks = await encryptStream(
          {data, chunkSize: 1048576, queueSize: 1});
        chunks.length.should.eql(1);
        for(const chunk of chunks) {
          chunk.jwe.should.be.a.JWE;
        }
        const result = await decryptStream({chunks});
        result.length.should.eql(data.length);
        result.should.deep.eql(data);
      });

      it('should decrypt a legacy-encrypted simple object', async function() {
        // decrypts `C20P` JWE (now replaced by `XC20P`)
        const jwe = LEGACY_JWE;
        keyAgreementKey = new KaK({
          keyPair: LEGACY_KEY_PAIR,
          id: 'urn:123'
        });
        const obj = {simple: true};
        jwe.should.be.a.JWE;
        const result = await cipher.decryptObject({jwe, keyAgreementKey});
        result.should.eql(obj);
      });
    });
  });
});
