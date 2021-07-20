/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
import crypto from '../crypto.js';
import * as base64url from 'base64url-universal';

class Kek {
  constructor(key) {
    this.key = key;
    this.algorithm = {name: 'A256KW'};
  }

  /**
   * Wraps a cryptographic key.
   *
   * @param {object} options - The options to use.
   * @param {Uint8Array} options.unwrappedKey - The key material as a
   *   `Uint8Array`.
   *
   * @returns {Promise<string>} - The base64url-encoded wrapped key bytes.
   */
  async wrapKey({unwrappedKey}) {
    const kek = this.key;
    // Note: `AES-GCM` algorithm name doesn't matter; will be exported raw.
    const extractable = true;

    unwrappedKey = await crypto.subtle.importKey(
      'raw', unwrappedKey, {name: 'AES-GCM', length: 256},
      extractable, ['wrapKey']);
    const wrappedKey = await crypto.subtle.wrapKey(
      'raw', unwrappedKey, kek, kek.algorithm);
    console.log(wrappedKey, '<><><><>wrappedKey:wrapKey()');
    return base64url.encode(new Uint8Array(wrappedKey));
  }

  /**
   * Unwraps a cryptographic key.
   *
   * @param {object} options - The options to use.
   * @param {string} options.wrappedKey - The wrapped key material as a
   *   base64url-encoded string.
   *
   * @returns {Promise<Uint8Array>} - Resolves to the key bytes or null if
   *   the unwrapping fails because the key does not match.
   */
  async unwrapKey({wrappedKey}) {
    const kek = this.key;
    // Note: `AES-GCM` algorithm name doesn't matter; will be exported raw.
    wrappedKey = base64url.decode(wrappedKey);
    try {
      const extractable = true;
      console.log(kek, '<><><><><><>kek:unwrapKey()');
      console.log(wrappedKey, 'wrappedKey:unwrapKey()<><><><>');
      const wrappedKeyUintArray = new Uint8Array(wrappedKey);
      const key = await crypto.subtle.unwrapKey(
        'raw', wrappedKeyUintArray, kek, kek.algorithm,
        {name: 'AES-KW'}, extractable, ['unwrapKey']);
      console.log(key, '<><><><><>key:unwrapKey()');
      const keyBytes = await crypto.subtle.exportKey('raw', key);
      return new Uint8Array(keyBytes);
    } catch(e) {
      console.log(e, 'e<><><><><><>');
      // decryption failed
      return null;
    }
  }
}

export async function createKek({keyData}) {
  const extractable = true;
  const key = await crypto.subtle.importKey(
    'raw', keyData, {name: 'AES-KW', length: 256}, extractable,
    ['wrapKey', 'unwrapKey']);
  return new Kek(key);
}
