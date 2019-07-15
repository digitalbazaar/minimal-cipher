/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

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
   * @param {Object} options - The options to use.
   * @param {Uint8Array} options.unwrappedKey - The key material as a
   *   Uint8Array.
   *
   * @returns {Promise<string>} The base64url-encoded wrapped key bytes.
   */
  async wrapKey({unwrappedKey}) {
    const kek = this.key;
    // Note: `AES-GCM` algorithm name doesn't matter; will be exported raw.
    const extractable = true;
    unwrappedKey = await crypto.subtle.importKey(
      'raw', unwrappedKey, {name: 'AES-GCM', length: 256},
      extractable, ['encrypt']);
    const wrappedKey = await crypto.subtle.wrapKey(
      'raw', unwrappedKey, kek, kek.algorithm);
    return base64url.encode(new Uint8Array(wrappedKey));
  }

  /**
   * Unwraps a cryptographic key.
   *
   * @param {Object} options - The options to use.
   * @param {string} options.wrappedKey - The wrapped key material as a
   *   base64url-encoded string.
   *
   * @returns {Promise<Uint8Array>} The key bytes.
   */
  async unwrapKey({wrappedKey}) {
    const kek = this.key;

    // Note: `AES-GCM` algorithm name doesn't matter; will be exported raw.
    wrappedKey = base64url.decode(wrappedKey);
    const extractable = true;
    const key = await crypto.subtle.unwrapKey(
      'raw', wrappedKey, kek, kek.algorithm,
      {name: 'AES-GCM'}, extractable, ['encrypt']);
    const keyBytes = await crypto.subtle.exportKey('raw', key);
    return new Uint8Array(keyBytes);
  }
}

export async function createKek({keyData}) {
  const extractable = true;
  const key = await crypto.subtle.importKey(
    'raw', keyData, {name: 'AES-KW', length: 256}, extractable,
    ['wrapKey', 'unwrapKey']);
  return new Kek({key});
}
