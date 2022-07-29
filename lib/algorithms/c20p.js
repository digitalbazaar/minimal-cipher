/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import crypto from 'node:crypto';
import {default as webcrypto} from '../crypto.js';

export const JWE_ENC = 'C20P';

/**
 * Generates a content encryption key (CEK). The 256-bit key is intended to be
 * used as a ChaCha20Poly1305 (RFC8439) key.
 *
 * @returns {Promise<Uint8Array>} - Resolves to the generated key.
 */
export async function generateKey() {
  // generate content encryption key
  return webcrypto.getRandomValues(new Uint8Array(32));
}

/**
 * Encrypts some data. The data will be encrypted using the given
 * 256-bit ChaCha20Poly1305 (RFC8439) content encryption key (CEK).
 *
 * @param {object} options - The options to use.
 * @param {Uint8Array} options.data - The data to encrypt.
 * @param {Uint8Array} [options.additionalData] - Optional additional
 *   authentication data.
 * @param {Uint8Array} options.cek - The content encryption key to use.
 *
 * @returns {Promise<object>} - Resolves to `{ciphertext, iv, tag}`.
 */
export async function encrypt({data, additionalData, cek}) {
  if(!(data instanceof Uint8Array)) {
    throw new TypeError('"data" must be a Uint8Array.');
  }
  if(!(cek instanceof Uint8Array)) {
    throw new TypeError('"cek" must be a Uint8Array.');
  }
  return _encrypt({data, additionalData, cek});
}

/**
 * Decrypts some encrypted data. The data must have been encrypted using
 * the given ChaCha20Poly1305 (RFC8439) content encryption key (CEK).
 *
 * @param {object} options - The options to use.
 * @param {Uint8Array} options.ciphertext - The data to decrypt.
 * @param {Uint8Array} options.iv - The initialization vector (aka nonce).
 * @param {Uint8Array} options.tag - The authentication tag.
 * @param {Uint8Array} [options.additionalData] - Optional additional
 *   authentication data.
 * @param {Uint8Array} options.cek - The content encryption key to use.
 *
 * @returns {Promise<Uint8Array>} The decrypted data.
 */
export async function decrypt({ciphertext, iv, tag, additionalData, cek}) {
  if(!(iv instanceof Uint8Array)) {
    throw new Error('Invalid or missing "iv".');
  }
  if(!(ciphertext instanceof Uint8Array)) {
    throw new Error('Invalid or missing "ciphertext".');
  }
  if(!(tag instanceof Uint8Array)) {
    throw new Error('Invalid or missing "tag".');
  }
  if(!(cek instanceof Uint8Array)) {
    throw new TypeError('"cek" must be a Uint8Array.');
  }

  // decrypt `ciphertext` using node.js native implementation
  const decipher = crypto.createDecipheriv(
    'chacha20-poly1305', cek, iv, {authTagLength: 16});
  decipher.setAuthTag(tag);
  if(additionalData) {
    decipher.setAAD(additionalData);
  }
  const decrypted = decipher.update(ciphertext);
  const final = decipher.final();
  return final.length > 0 ? Buffer.concat([decrypted, final]) : decrypted;
}

// internal function exported for reuse by XChaCha20Poly1305
export async function _encrypt({data, additionalData, cek, iv}) {
  // Note: Use of a random value here as a counter is only viable for a
  // limited set of messages; using XChaCha20Poly1305 instead
  // probabilistically eliminates chances of a collision as it has a 192-bit IV
  if(iv === undefined) {
    iv = webcrypto.getRandomValues(new Uint8Array(12));
  }

  // encrypt `data` using node.js native implementation
  const cipher = crypto.createCipheriv(
    'chacha20-poly1305', cek, iv, {authTagLength: 16});
  if(additionalData) {
    cipher.setAAD(additionalData);
  }
  const encrypted = cipher.update(data);
  const final = cipher.final();
  const ciphertext = final.length > 0 ?
    Buffer.concat([encrypted, final]) : encrypted;
  const tag = cipher.getAuthTag();

  return {ciphertext, iv, tag};
}

// internal function exported for reuse by XChaCha20Poly1305
export function _chacha20({key, nonce, src}) {
  // use node.js implementation
  const cipher = crypto.createCipheriv('chacha20', key, nonce);
  const dst = cipher.update(src);
  const final = cipher.final();
  return final.length > 0 ? Buffer.concat([dst, final]) : dst;
}
