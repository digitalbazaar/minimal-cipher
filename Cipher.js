/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import base64url from 'base64url-universal';
import {TextDecoder, TextEncoder} from './util.js';
import * as fipsAlgorithm from './algorithms/fips.js';
import * as recAlgorithm from './algorithms/recommended.js';

const VERSIONS = ['recommended', 'fips'];
const CIPHER_ALGORITHMS = {
  [fipsAlgorithm.cipher.JWE_ENC]: fipsAlgorithm.cipher,
  [recAlgorithm.cipher.JWE_ENC]: recAlgorithm.cipher
};
const KEY_AGREEMENT_ALGORITHMS = {
  [fipsAlgorithm.keyAgreement.JWE_ALG]: fipsAlgorithm.keyAgreement,
  [recAlgorithm.keyAgreement.JWE_ALG]: recAlgorithm.keyAgreement
};

export class Cipher {
  /**
   * Creates a new Cipher instance that can be used to encrypt or decrypt
   * data. A version must be supplied for encrypting data; the version
   * indicates whether a FIPS-compliant algorithm or the latest recommended
   * algorithm will be used.
   *
   * @param {String} [version='recommended'] `fips` to use a FIPS-compliant
   *   algorithm, `recommended` to use the latest recommended algorithm when
   *   encrypting.
   *
   * @return {Cipher}.
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
   * Encrypts some data. If `recipients` is not empty, then the given `kek`
   * must be present in the array or an error will be thrown. If an existing
   * wrapped content encryption key (CEK) can be found in `recipients` for
   * `kek`, then it will be unwrapped and reused. Otherwise, a new CEK will be
   * generated. If a new CEK is to be generated, then all other recipients must
   * reference an accessible Diffie-Hellman public key so that this method can
   * wrap the CEK for them.
   *
   * @param {Uint8Array|String} data the data to encrypt.
   * @param {Object} [kek=undefined] a key encryption key API with `id`,
   *   `wrapKey`, and `unwrapKey`.
   * @param {function} [getKey=undefined] a function that returns a Promise
   *   that resolves to a DH public key, given its key ID.
   * @param {Array} [recipients=[]] an array of recipients for the encrypted
   *   content.
   * @param {String} [wrappedCek] a base64url-encoded CEK.
   *
   * @return {Promise<Object>} resolves to a JWE.
   */
  async encrypt({data, kek, getKey, recipients = []}) {
    // TODO: remove `kek` entirely
    // TODO: do we want to call `getKey` `keyResolver` instead?
    if(!Array.isArray(recipients)) {
      throw new TypeError('"recipients" must be an array.');
    }
    if(kek) {
      if(typeof kek !== 'object') {
        throw new TypeError('"kek" must be an object.');
      }
      if(recipients.length > 1) {
        throw new Error(
          'Encrypting for multiple recipients is only supported when every ' +
          'recipient uses a key agreement key.');
      }
    } else if(recipients.length === 0) {
      throw new Error('"kek" must be given when "recipients" is empty.');
    } else {
      // ensure all recipients use a supported key agreement algorithm
      const {keyAgreement: {JWE_ALG: alg}} = this;
      if(recipients.some(e => !e.header || e.header.alg !== alg)) {
        throw new Error(`All recipients must use the algorithm "${alg}".`);
      }
    }
    data = _strToUint8Array(data);
    const {cipher} = this;

    // create new recipient or find existing one that matches KEK
    let recipient;
    recipients = recipients.slice();
    if(recipients.length === 0) {
      // kek not added to recipients yet, copy recipients and add it
      recipient = {
        header: {
          alg: kek.algorithm,
          kid: kek.id
        }
      };
      recipients.push(recipient);
    } else if(kek) {
      // find matching kek in `recipients`
      recipient = _findRecipient(recipients, kek);
      if(!recipient) {
        throw new Error('"kek" not found in "recipients".');
      }
    }

    // generate a CEK for encrypting the content
    const cek = await cipher.generateKey();

    if(kek) {
      // wrap cek for single recipient using KEK
      recipient.encrypted_key = await kek.wrapKey({unwrappedKey: cek});
    } else {
      // fetch all public DH keys
      const publicKeys = await Promise.all(
        recipients.map(e => getKey({id: e.header.kid})));

      // wrap cek for each recipient by deriving shared keys
      const {keyAgreement} = this;
      const derivedKeys = await Promise.all(
        publicKeys.map(
          peerPublicKey => keyAgreement.kekFromStaticPeer({peerPublicKey})));

      // TODO: convert derived keys into JOSE header format `epk`, etc.

      throw new Error('Not implemented.');
    }

    // create shared protected header as associated authenticated data (aad)
    // ASCII(BASE64URL(UTF8(JWE Protected Header)))
    const enc = cipher.JWE_ENC;
    const jweProtectedHeader = JSON.stringify({enc});
    const _protected = base64url.encode(_strToUint8Array(jweProtectedHeader));
    // UTF8-encoding a base64url-encoded string is the same as ASCII
    const additionalData = _strToUint8Array(_protected);

    // encrypt data
    const {ciphertext, iv, tag} = await cipher.encrypt(
      {data, additionalData, cek});

    // represent encrypted data as JWE
    const jwe = {
      protected: _protected,
      recipients,
      iv: base64url.encode(iv),
      ciphertext: base64url.encode(ciphertext),
      tag: base64url.encode(tag)
    };
    return jwe;
  }

  /**
   * Encrypts an object. The object will be serialized to JSON and passed
   * to `encrypt`. See `encrypt` for other parameters.
   *
   * @param {Object} obj the object to encrypt.
   *
   * @return {Promise<Object>} resolves to a JWE.
   */
  async encryptObject({obj, ...rest}) {
    if(typeof obj !== 'object') {
      throw new TypeError('"obj" must be an object.');
    }
    return this.encrypt({data: JSON.stringify(obj), ...rest});
  }

  /**
   * Decrypts a JWE. The only JWEs currently supported use an `alg` of `A256KW`
   * and `enc` of `A256GCM` or `C20P`. These parameters refer to data that has
   * been encrypted using a 256-bit AES-GCM or ChaCha20Poly1305 content
   * encryption key CEK that has been wrapped using a 256-bit AES-KW key
   * encryption key KEK.
   *
   * @param {Object} jwe the JWE to decrypt.
   * @param {Object} [kek=undefined] a key encryption key API with `id`,
   *   `wrap`, and `unwrap`.
   * @param {Object} [keyAgreementKey=undefined] a key agreement key API with
   *   `id` and `deriveSecret`.
   *
   * @return {Promise<Uint8Array|null>} resolves to the decrypted data or
   *   `null` if the decryption failed.
   */
  async decrypt({jwe, kek, keyAgreementKey}) {
    // validate JWE
    if(!(jwe && typeof jwe === 'object')) {
      throw new TypeError('"jwe" must be an object.');
    }
    if(typeof jwe.protected !== 'string') {
      throw new TypeError('"jwe.protected" is missing or not a string.');
    }
    if(typeof jwe.iv !== 'string') {
      throw new Error('Invalid or missing "iv".');
    }
    if(typeof jwe.ciphertext !== 'string') {
      throw new Error('Invalid or missing "ciphertext".');
    }
    if(typeof jwe.tag !== 'string') {
      throw new Error('Invalid or missing "tag".');
    }

    // validate encryption header
    let header;
    let additionalData;
    try {
      // ASCII(BASE64URL(UTF8(JWE Protected Header)))
      additionalData = _strToUint8Array(jwe.protected);
      header = JSON.parse(new TextDecoder().decode(
        base64url.decode(jwe.protected)));
    } catch(e) {
      throw new Error('Invalid JWE "protected" header.');
    }
    if(!(header.enc && typeof header.enc === 'string')) {
      throw new Error('Invalid JWE "enc" header.');
    }
    const cipher = CIPHER_ALGORITHMS[header.enc];
    if(!cipher) {
      throw new Error('Unsupported encryption algorithm "${header.enc}".');
    }
    if(!Array.isArray(jwe.recipients)) {
      throw new TypeError('"jwe.recipients" must be an array.');
    }

    // find wrapped key for `kek` or `keyAgreementKey`
    let recipient;
    if(kek) {
      recipient = _findRecipient(jwe.recipients, kek);
      if(!recipient) {
        throw new Error('No matching recipient found for KEK.');
      }
    } else {
      recipient = _findRecipient(jwe.recipients, keyAgreementKey);
      if(!recipient) {
        throw new Error('No matching recipient found for key agreement key.');
      }
      // TODO: generate `kek` API instance from key agreement key
    }
    const {encrypted_key: wrappedKey} = recipient;

    if(typeof wrappedKey !== 'string') {
      throw new Error('Invalid or missing "encrypted_key".');
    }

    // unwrap CEK and decrypt content
    const cek = await kek.unwrapKey({wrappedKey});
    const {ciphertext, iv, tag} = jwe;
    return cipher.decrypt({
      ciphertext: base64url.decode(ciphertext),
      iv: base64url.decode(iv),
      tag: base64url.decode(tag),
      additionalData,
      cek
    });
  }

  /**
   * Decrypts a JWE that must contain an encrypted object. This method will
   * call `decrypt` and then `JSON.parse` the resulting decrypted UTF-8 data.
   *
   * @param {Object} jwe the JWE to decrypt.
   * @param {Object} [kek=undefined] a key encryption key API with `id`,
   *   `wrap`, and `unwrap`.
   * @param {Object} [keyAgreementKey=undefined] a key agreement key API with
   *   `id` and `deriveSecret`.
   *
   * @return {Promise<Object|null>} resolves to the decrypted object or `null`
   *   if the decryption failed.
   */
  async decryptObject({jwe, kek, keyAgreementKey}) {
    const data = await this.decrypt({jwe, kek, keyAgreementKey});
    if(!data) {
      // decryption failed
      return null;
    }
    return JSON.parse(new TextDecoder().decode(data));
  }
}

function _findRecipient(recipients, key) {
  return recipients.find(
    e => e.header && e.header.kid === key.id &&
    (!key.algorithm || (e.header.alg === key.algorithm)));
}

function _strToUint8Array(data) {
  if(typeof data === 'string') {
    // convert data to Uint8Array
    return new TextEncoder().encode(data);
  }
  if(!(data instanceof Uint8Array)) {
    throw new TypeError('"data" be a string or Uint8Array.');
  }
  return data;
}
