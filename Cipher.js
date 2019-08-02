/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import base64url from 'base64url-universal';
import {TextDecoder, TransformStream, stringToUint8Array} from './util.js';
import {DecryptTransformer} from './DecryptTransformer.js';
import {EncryptTransformer} from './EncryptTransformer.js';
import * as fipsAlgorithm from './algorithms/fips.js';
import * as recAlgorithm from './algorithms/recommended.js';

const VERSIONS = ['recommended', 'fips'];

export class Cipher {
  /**
   * Creates a new Cipher instance that can be used to encrypt or decrypt
   * data. A version must be supplied for encrypting data; the version
   * indicates whether a FIPS-compliant algorithm or the latest recommended
   * algorithm will be used.
   *
   * @param {string} [version='recommended'] - `fips` to use a FIPS-compliant
   *   algorithm, `recommended` to use the latest recommended algorithm when
   *   encrypting.
   *
   * @returns {Cipher} A Cipher used to encrypt and decrypt data.
   */
  constructor({version = 'recommended'} = {}) {
    if(typeof version !== 'string') {
      throw new TypeError('"version" must be a string.');
    }
    if(!VERSIONS.includes(version)) {
      throw new Error(`Unsupported version "${version}".`);
    }
    this.version = version;
    if(version === 'fips') {
      this.cipher = fipsAlgorithm.cipher;
      this.keyAgreement = fipsAlgorithm.keyAgreement;
    } else {
      this.cipher = recAlgorithm.cipher;
      this.keyAgreement = recAlgorithm.keyAgreement;
    }
  }

  /**
   * Creates a TransformStream that will encrypt some data for one or more
   * recipients and output a stream of chunks, each containing an object
   * with the property `jwe` with a JWE value.
   *
   * A list of recipients must be given in the `recipients` array, identified
   * by key agreement keys. An ephemeral ECDH key will be generated and used to
   * derive shared KEKs that will wrap a randomly generated CEK. Each recipient
   * in the `recipients` array will be updated to include the generated
   * ephemeral ECDH key.
   *
   * @param {object} options - The options for the stream.
   * @param {Array} options.recipients
   * - An array of recipients for the encrypted content.
   * @param {Function} options.keyResolver - A function that returns a Promise
   *   that resolves a key ID to a DH public key.
   * @param {number} [options.chunkSize=1048576]
   * - The size, in bytes, of the chunks to break the incoming data into.
   *
   * @returns {Promise<TransformStream>} Resolves to a TransformStream.
   */
  async createEncryptStream({recipients, keyResolver, chunkSize}) {
    const transformer = await this.createEncryptTransformer(
      {recipients, keyResolver, chunkSize});
    return new TransformStream(transformer);
  }

  /**
   * Creates a TransformStream that will decrypt one or more chunks, each one
   * that is an object with a `jwe` property that has a JWE as a value. The
   * stream will output chunks of Uint8Arrays consisting of the decrypted
   * data from each chunk.
   *
   * The only JWEs currently supported use an `alg` of `ECDH-ES+A256KW` and
   * `enc` of `A256GCM` or `C20P`. These parameters refer to data that has been
   * encrypted using a 256-bit AES-GCM or ChaCha20Poly1305 content encryption
   * key (CEK) that has been wrapped using a 256-bit AES-KW key encryption key
   * (KEK) generated via a shared secret between an ephemeral ECDH key and a
   * static ECDH key (ECDH-ES).
   *
   * @param {object} options - Options for createDecryptStream.
   * @param {object} options.keyAgreementKey
   * - A key agreement key API with `id` and deriveSecret`.
   *
   * @returns {Promise<TransformStream>} Resolves to the TransformStream.
   */
  async createDecryptStream({keyAgreementKey}) {
    const transformer = await this.createDecryptTransformer(
      {keyAgreementKey});
    return new TransformStream(transformer);
  }

  /**
   * Encrypts some data for one or more recipients and outputs a JWE. The
   * data to encrypt can be given as a Uint8Array or a string.
   *
   * A list of recipients must be given in the `recipients` array, identified
   * by key agreement keys. An ephemeral ECDH key will be generated and used to
   * derive shared KEKs that will wrap a randomly generated CEK. Each recipient
   * in the `recipients` array will be updated to include the generated
   * ephemeral ECDH key.
   *
   * @param {object} options - Options for encrypt.
   * @param {Uint8Array|string} [options.data] - The data to encrypt.
   * @param {Array} options.recipients
   * - An array of recipients for the encrypted content.
   * @param {Function} options.keyResolver - A function that returns a Promise
   *   that resolves a key ID to a DH public key.
   *
   * @returns {Promise<object>} Resolves to a JWE.
   */
  async encrypt({data, recipients, keyResolver}) {
    if(!(data instanceof Uint8Array) && typeof data !== 'string') {
      throw new TypeError('"data" must be a Uint8Array or a string.');
    }
    if(data) {
      data = stringToUint8Array(data);
    }
    const transformer = await this.createEncryptTransformer(
      {recipients, keyResolver});
    return transformer.encrypt(data);
  }

  /**
   * Encrypts an object. The object will be serialized to JSON and passed
   * to `encrypt`. See `encrypt` for other parameters.
   *
   * @param {object} obj - The object to encrypt.
   *
   * @returns {Promise<object>} Resolves to a JWE.
   */
  async encryptObject({obj, ...rest}) {
    if(typeof obj !== 'object') {
      throw new TypeError('"obj" must be an object.');
    }
    return this.encrypt({data: JSON.stringify(obj), ...rest});
  }

  /**
   * Decrypts a single JWE.
   *
   * The only JWEs currently supported use an `alg` of `ECDH-ES+A256KW` and
   * `enc` of `A256GCM` or `C20P`. These parameters refer to data that has been
   * encrypted using a 256-bit AES-GCM or ChaCha20Poly1305 content encryption
   * key (CEK) that has been wrapped using a 256-bit AES-KW key encryption key
   * (KEK) generated via a shared secret between an ephemeral ECDH key and a
   * static ECDH key (ECDH-ES).
   *
   * @param {object} options - Options for decrypt.
   * @param {object} options.jwe - The JWE to decrypt.
   * @param {object} options.keyAgreementKey
   * - A key agreement key API with `id` and
   *   `deriveSecret`.
   *
   * @returns {Promise<Uint8Array|null>} Resolves to the decrypted data
   *   or `null` if the decryption failed.
   */
  async decrypt({jwe, keyAgreementKey}) {
    const transformer = await this.createDecryptTransformer(
      {keyAgreementKey});
    return transformer.decrypt(jwe);
  }

  /**
   * Decrypts a JWE that must contain an encrypted object. This method will
   * call `decrypt` and then `JSON.parse` the resulting decrypted UTF-8 data.
   *
   * @param {object} options - Options.
   * @param {object} options.jwe - The JWE to decrypt.
   * @param {object} options.keyAgreementKey
   * - A key agreement key API with `id` and `deriveSecret`.
   *
   * @returns {Promise<object|null>} Resolves to the decrypted object or `null`
   *   if the decryption failed.
   */
  async decryptObject({jwe, keyAgreementKey}) {
    const data = await this.decrypt({jwe, keyAgreementKey});
    if(!data) {
      // decryption failed
      return null;
    }
    return JSON.parse(new TextDecoder().decode(data));
  }

  /**
   * Creates an EncryptTransformer that can be used to encrypt one or more
   * chunks of data.
   *
   * A list of recipients must be given in the `recipients` array, identified
   * by key agreement keys. An ephemeral ECDH key will be generated and used to
   * derive shared KEKs that will wrap a randomly generated CEK. Each recipient
   * in the `recipients` array will be updated to include the generated
   * ephemeral ECDH key.
   *
   * @param {object} options - Options for the transformer.
   * @param {Array} options.recipients
   * - An array of recipients for the encrypted content.
   * @param {Function} options.keyResolver - A function that returns
   * a Promise that resolves a key ID to a DH public key.
   * @param {number} [options.chunkSize=1048576]
   * - The size, in bytes, of the chunks to
   *   break the incoming data into (only applies if returning a stream).
   *
   * @returns {Promise<EncryptTransformer>} Resolves to an EncryptTransformer.
   */
  async createEncryptTransformer({recipients, keyResolver, chunkSize}) {
    if(!(Array.isArray(recipients) && recipients.length > 0)) {
      throw new TypeError('"recipients" must be a non-empty array.');
    }
    // ensure all recipients use the supported key agreement algorithm
    const {keyAgreement} = this;
    const {JWE_ALG: alg} = keyAgreement;
    if(!recipients.every(e => e.header && e.header.alg === alg)) {
      throw new Error(`All recipients must use the algorithm "${alg}".`);
    }
    const {cipher} = this;

    // generate a CEK for encrypting the content
    const cek = await cipher.generateKey();

    // fetch all public DH keys
    const publicKeys = await Promise.all(
      recipients.map(e => keyResolver({id: e.header.kid})));

    // derive ephemeral ECDH key pair to use with all recipients
    const ephemeralKeyPair = await keyAgreement.deriveEphemeralKeyPair();

    // derive KEKs for each recipient
    const derivedResults = await Promise.all(
      publicKeys.map(
        staticPublicKey => keyAgreement.kekFromStaticPeer(
          {ephemeralKeyPair, staticPublicKey})));

    // update all recipients with ephemeral ECDH key and wrapped CEK
    await Promise.all(recipients.map(async (recipient, i) => {
      const {kek, epk, apu, apv} = derivedResults[i];
      recipients[i] = recipient = {header: {...recipient.header}};
      recipient.header.epk = epk;
      recipient.header.apu = apu;
      recipient.header.apv = apv;
      recipient.encrypted_key = await kek.wrapKey({unwrappedKey: cek});
    }));

    // create shared protected header as associated authenticated data (aad)
    // ASCII(BASE64URL(UTF8(JWE Protected Header)))
    const enc = cipher.JWE_ENC;
    const jweProtectedHeader = JSON.stringify({enc});
    const encodedProtectedHeader =
      base64url.encode(stringToUint8Array(jweProtectedHeader));
    // UTF8-encoding a base64url-encoded string is the same as ASCII
    const additionalData = stringToUint8Array(encodedProtectedHeader);

    return new EncryptTransformer({
      recipients,
      encodedProtectedHeader,
      cipher,
      additionalData,
      cek,
      chunkSize
    });
  }

  /**
   * Creates a DecryptTransformer.
   *
   * @param {object} keyAgreementKey - A key agreement key API with `id` and
   *   `deriveSecret`.
   *
   * @returns {Promise<DecryptTransformer>} Resolves to a DecryptTransformer.
   */
  async createDecryptTransformer({keyAgreementKey}) {
    return new DecryptTransformer({
      keyAgreement: this.keyAgreement,
      keyAgreementKey
    });
  }
}
