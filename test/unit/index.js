/*!
 * Copyright (c) 2019-2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const chai = require('chai');
const {Cipher} = require('../../');
const {TextDecoder, ReadableStream} = require('../../util');
const KaK = require('../KaK');
const {isJWE, isRecipient} = require('../chai-cipher');
const {store} = require('../store');
const {LEGACY_JWE, LEGACY_KEY_PAIR} = require('../mock-data');

const should = chai.should();
chai.use(isJWE);

const cipherAlgorithms = ['recommended', 'fips'];

describe('minimal-cipher', function() {
  cipherAlgorithms.forEach(algorithm => {
    describe(`${algorithm} algorithm`, function() {

      // each test inits data to null
      let cipher, testKaK, recipient = null;

      // keyResolver returns publicKeyNode
      const keyResolver = async ({id}) => store.get(id);

      beforeEach(async function() {
        cipher = new Cipher({version: algorithm});
        testKaK = new KaK({id: 'urn:123'});
        recipient = [testKaK.recipient];
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
       *   JOSE recipients.
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
       * @param {KaK} options.keyAgreementKey - A KaK in the recipients.
       *
       * @returns {Promise<Uint8Array>} The unencrypted data.
       */
      async function decryptStream({chunks, keyAgreementKey = testKaK}) {
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
            throw e;
          }
        }
        return Uint8Array.from(data);
      }

      it('should encrypt a simple Uint8Array', async function() {
        const data = getRandomUint8();
        const result = await cipher.encrypt({
          data,
          recipients: recipient,
          keyResolver
        });
        result.should.be.a.JWE;
        result.recipients.length.should.equal(1);
        isRecipient({recipients: result.recipients, kak: testKaK});
      });

      it('should encrypt a simple Uint8Array with multiple recipients',
        async function() {
          const data = getRandomUint8();
          const secondKaK = new KaK({id: 'urn:recipient2'});
          const recipients = [...recipient, secondKaK.recipient];
          const result = await cipher.encrypt({
            data,
            recipients,
            keyResolver
          });
          result.should.be.a.JWE;
          result.recipients.length.should.equal(2);
          isRecipient({recipients: result.recipients, kak: testKaK});
          isRecipient({recipients: result.recipients, kak: secondKaK});
        });

      it('should fail if a recipient kid can not be resolved',
        async function() {
          const data = getRandomUint8();
          const secondKaK = new KaK({id: 'urn:recipient2'});
          const secondRecipient = {...secondKaK.recipient};
          secondRecipient.header.kid = 'urn:not-found';
          const recipients = [...recipient, secondRecipient];
          let error = null;
          let result = null;
          try {
            result = await cipher.encrypt({
              data,
              recipients,
              keyResolver
            });
          } catch(e) {
            error = e;
          }
          should.not.exist(result);
          should.exist(error);
          error.should.be.an('Error');
          error.message.should.equal('"staticPublicKey" is required.');
        });

      it('should encrypt a simple string', async function() {
        const data = 'simple';
        const result = await cipher.encrypt({
          data,
          recipients: recipient,
          keyResolver
        });
        result.should.be.a.JWE;
        result.recipients.length.should.equal(1);
        isRecipient({recipients: result.recipients, kak: testKaK});
      });

      it('should encrypt a simple object', async function() {
        const obj = {simple: true};
        const result = await cipher.encryptObject(
          {obj, recipients: recipient, keyResolver});
        result.should.be.a.JWE;
        result.recipients.length.should.equal(1);
        isRecipient({recipients: result.recipients, kak: testKaK});
      });

      it('should encrypt a simple object with multiple recipients',
        async function() {
          const obj = {simple: true};
          const secondKaK = new KaK({id: 'urn:recipient2'});
          const recipients = [...recipient, secondKaK.recipient];
          const result = await cipher.encryptObject(
            {obj, recipients, keyResolver});
          result.should.be.a.JWE;
          result.recipients.length.should.equal(2);
          isRecipient({recipients: result.recipients, kak: testKaK});
          isRecipient({recipients: result.recipients, kak: secondKaK});
        });

      it('should encrypt a stream', async function() {
        const data = getRandomUint8();
        const chunks = await encryptStream({data});
        chunks.length.should.be.gte(0);
        for(const chunk of chunks) {
          chunk.jwe.should.be.a.JWE;
          chunk.jwe.recipients.length.should.equal(1);
          isRecipient({recipients: chunk.jwe.recipients, kak: testKaK});
        }
      });

      it('should encrypt a stream with multiple recipients',
        async function() {
          const data = getRandomUint8();
          const secondKaK = new KaK({id: 'urn:recipient2'});
          const recipients = [...recipient, secondKaK.recipient];
          const chunks = await encryptStream({data, recipients});
          chunks.length.should.be.gte(0);
          for(const chunk of chunks) {
            chunk.jwe.should.be.a.JWE;
            chunk.jwe.recipients.length.should.equal(2);
            isRecipient({recipients: chunk.jwe.recipients, kak: testKaK});
            isRecipient({recipients: chunk.jwe.recipients, kak: secondKaK});
          }
        });

      it('should decrypt an Uint8Array', async function() {
        const data = getRandomUint8();
        const jwe = await cipher.encrypt({
          data,
          recipients: recipient,
          keyResolver
        });
        jwe.should.be.a.JWE;
        jwe.recipients.length.should.equal(1);
        isRecipient({recipients: jwe.recipients, kak: testKaK});
        const result = await cipher.decrypt({jwe, keyAgreementKey: testKaK});
        result.should.eql(data);
      });

      it('should decrypt an Uint8Array with multiple recipients',
        async function() {
          const data = getRandomUint8();
          const secondKaK = new KaK({id: 'urn:recipient2'});
          const recipients = [...recipient, secondKaK.recipient];
          const jwe = await cipher.encrypt({
            data,
            recipients,
            keyResolver
          });
          jwe.should.be.a.JWE;
          jwe.recipients.length.should.equal(2);
          isRecipient({recipients: jwe.recipients, kak: testKaK});
          isRecipient({recipients: jwe.recipients, kak: secondKaK});
          const result = await cipher.decrypt({jwe, keyAgreementKey: testKaK});
          result.should.eql(data);
          const result2 = await cipher.decrypt(
            {jwe, keyAgreementKey: secondKaK});
          result2.should.eql(data);
        });

      it('should decrypt a simple string', async function() {
        const data = 'simple';
        const jwe = await cipher.encrypt({
          data,
          recipients: recipient,
          keyResolver
        });
        jwe.should.be.a.JWE;
        jwe.recipients.length.should.equal(1);
        isRecipient({recipients: jwe.recipients, kak: testKaK});
        const result = await cipher.decrypt({jwe, keyAgreementKey: testKaK});
        const resultString = new TextDecoder().decode(result);
        resultString.should.eql(data);
      });

      it('should decrypt a simple object', async function() {
        const obj = {simple: true};
        const jwe = await cipher.encryptObject(
          {obj, recipients: recipient, keyResolver});
        jwe.should.be.a.JWE;
        jwe.recipients.length.should.equal(1);
        isRecipient({recipients: jwe.recipients, kak: testKaK});
        const result = await cipher.decryptObject(
          {jwe, keyAgreementKey: testKaK});
        result.should.eql(obj);
      });

      it('should decrypt a simple object with multiple recipients',
        async function() {
          const obj = {simple: true};
          const secondKaK = new KaK({id: 'urn:recipient2'});
          const recipients = [...recipient, secondKaK.recipient];
          const jwe = await cipher.encryptObject(
            {obj, recipients, keyResolver});
          jwe.should.be.a.JWE;
          jwe.recipients.length.should.equal(2);
          isRecipient({recipients: jwe.recipients, kak: testKaK});
          isRecipient({recipients: jwe.recipients, kak: secondKaK});
          const result = await cipher.decryptObject(
            {jwe, keyAgreementKey: testKaK});
          result.should.eql(obj);
          const result2 = await cipher.decryptObject(
            {jwe, keyAgreementKey: secondKaK});
          result2.should.eql(obj);
        });

      it('should decrypt a stream with chunkSize 1 byte', async function() {
        const data = getRandomUint8({size: 100});
        const chunks = await encryptStream({data, chunkSize: 1});
        chunks.length.should.equal(100);
        for(const chunk of chunks) {
          chunk.jwe.should.be.a.JWE;
          chunk.jwe.recipients.length.should.equal(1);
          isRecipient({recipients: chunk.jwe.recipients, kak: testKaK});
        }
        const result = await decryptStream({chunks});
        result.length.should.equal(data.length);
        result.should.deep.eql(data);
      });

      it('should decrypt a stream with chunkSize 5 bytes', async function() {
        const data = getRandomUint8({size: 100});
        const chunks = await encryptStream({data, chunkSize: 5});
        chunks.length.should.equal(20);
        for(const chunk of chunks) {
          chunk.jwe.should.be.a.JWE;
          chunk.jwe.recipients.length.should.equal(1);
          isRecipient({recipients: chunk.jwe.recipients, kak: testKaK});
        }
        const result = await decryptStream({chunks});
        result.length.should.equal(data.length);
        result.should.deep.eql(data);
      });

      it('should decrypt a stream with chunkSize 1 megabyte', async function() {
        const data = getRandomUint8({size: 100});
        const chunks = await encryptStream(
          {data, chunkSize: 1048576, queueSize: 1});
        chunks.length.should.equal(1);
        for(const chunk of chunks) {
          chunk.jwe.should.be.a.JWE;
          chunk.jwe.recipients.length.should.equal(1);
          isRecipient({recipients: chunk.jwe.recipients, kak: testKaK});
        }
        const result = await decryptStream({chunks});
        result.length.should.equal(data.length);
        result.should.deep.eql(data);
      });

      it('should decrypt a stream with multiple recipients',
        async function() {
          const data = getRandomUint8({size: 100});
          const secondKaK = new KaK({id: 'urn:recipient2'});
          const recipients = [...recipient, secondKaK.recipient];
          const chunks = await encryptStream({data, chunkSize: 1, recipients});
          chunks.length.should.equal(100);
          for(const chunk of chunks) {
            chunk.jwe.should.be.a.JWE;
            chunk.jwe.recipients.length.should.equal(2);
            isRecipient({recipients: chunk.jwe.recipients, kak: testKaK});
            isRecipient({recipients: chunk.jwe.recipients, kak: secondKaK});
          }
          const result = await decryptStream(
            {chunks, keyAgreementKey: testKaK});
          result.length.should.equal(data.length);
          result.should.deep.eql(data);
          const result2 = await decryptStream(
            {chunks, keyAgreementKey: secondKaK});
          result2.length.should.equal(data.length);
          result2.should.deep.eql(data);
        });

      it('should only decrypt stream if KaK matches a recipient',
        async function() {
          const data = getRandomUint8({size: 100});
          const secondKaK = new KaK({id: 'urn:recipient2'});
          const recipients = [...recipient, secondKaK.recipient];
          const chunks = await encryptStream({data, chunkSize: 1, recipients});
          chunks.length.should.equal(100);
          for(const chunk of chunks) {
            chunk.jwe.should.be.a.JWE;
            chunk.jwe.recipients.length.should.equal(2);
            isRecipient({recipients: chunk.jwe.recipients, kak: testKaK});
            isRecipient({recipients: chunk.jwe.recipients, kak: secondKaK});
            // remove the testKaK
            chunk.jwe.recipients = chunk.jwe.recipients.filter(
              r => r.header.kid != testKaK.id);
          }
          let error = null;
          let result = null;
          try {
            // the testKaK should fail to decrypt
            result = await decryptStream({chunks, keyAgreementKey: testKaK});
          } catch(e) {
            error = e;
          }
          should.not.exist(result);
          should.exist(error);
          error.should.be.an('Error');
          error.message.should.equal(
            'No matching recipient found for key agreement key.');
          // the secondKaK should still be able to decrypt
          result = await decryptStream(
            {chunks, keyAgreementKey: secondKaK});
          result.length.should.equal(data.length);
          result.should.deep.eql(data);
        });

      it('should decrypt a legacy-encrypted simple object', async function() {
        // decrypts `C20P` JWE (now replaced by `XC20P`)
        const jwe = LEGACY_JWE;
        testKaK = new KaK({
          keyPair: LEGACY_KEY_PAIR,
          id: 'urn:123'
        });
        const obj = {simple: true};
        jwe.should.be.a.JWE;
        jwe.recipients.length.should.equal(1);
        isRecipient({recipients: jwe.recipients, kak: testKaK});
        const result = await cipher.decryptObject(
          {jwe, keyAgreementKey: testKaK});
        result.should.eql(obj);
      });
    });
  });
});
