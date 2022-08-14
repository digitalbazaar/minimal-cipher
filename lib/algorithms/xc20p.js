/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import crypto from '../crypto.js';
import {_encrypt, decrypt as _decrypt, _chacha20} from './c20p.js';

// constants are based on the string: "expand 32-byte k"
const CHACHA20_CONSTANTS = [
  0x61707865, // "expa" referred to as the "sigma" constant
  0x3320646E, // "nd 3" keys used here must be 32-bytes
  0x79622D32, // "2-by"
  0x6B206574, // "te k"
];
const LE = true;
const NULL_DATA = new Uint8Array(64);

export const JWE_ENC = 'XC20P';

/**
 * Generates a content encryption key (CEK). The 256-bit key is intended to be
 * used as a XChaCha20Poly1305 (draft-irtf-cfrg-xchacha-01) key.
 *
 * @returns {Promise<Uint8Array>} - Resolves to the generated key.
 */
export async function generateKey() {
  // generate content encryption key
  return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * Encrypts some data. The data will be encrypted using the given
 * 256-bit XChaCha20Poly1305 (draft-irtf-cfrg-xchacha-01) content encryption
 * key (CEK).
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

  // generate 24-byte (192-bit) XChaCha20Poly1305 IV and use it and `cek` to
  // generate subkey and 12-byte (96-bit) IV for use with ChaCha20Poly1305
  const nonce = crypto.getRandomValues(new Uint8Array(24));
  const {subkey, iv} = await _generateSubkey({cek, nonce});

  // run ChaCha20Poly1305
  const result = await _encrypt({data, additionalData, cek: subkey, iv});
  // return full XChaCha20Poly1305 nonce as IV
  result.iv = nonce;
  // wipe generated values
  subkey.fill(0);
  iv.fill(0);
  return result;
}

/**
 * Decrypts some encrypted data. The data must have been encrypted using
 * the given XChaCha20Poly1305 (draft-irtf-cfrg-xchacha-01) content encryption
 * key (CEK).
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

  // generate subkey and 12-byte (96-bit) IV for use with ChaCha20Poly1305 from
  // `cek` and 24-byte (192-bit) XChaCha20Poly1305 IV
  const {subkey, iv: newIV} = await _generateSubkey({cek, nonce: iv});

  // decrypt `ciphertext`
  const result = await _decrypt(
    {ciphertext, iv: newIV, tag, additionalData, cek: subkey});
  // wipe generated values
  subkey.fill(0);
  newIV.fill(0);
  return result;
}

async function _generateSubkey({cek, nonce}) {
  // generate subkey and 12-byte IV for ChaCha20Poly1305; first 4 bytes of
  // IV are NULL bytes, last 8 are the last 8 bytes of the randomly generated
  // 24-byte XChaCha20Poly1305 nonce
  const subkey = await _hchacha20({key: cek, nonce: nonce.subarray(0, 16)});
  const iv = new Uint8Array(12);
  iv.set(nonce.subarray(16), 4);
  return {subkey, iv};
}

async function _hchacha20({key, nonce}) {
  /* HChaCha20's output is the first 16 bytes of internal state and last 16
  bytes of ChaCha20 internal state after running its usual rounds. See:

  https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha#section-2.2

  ChaCha20's output is each 4 bytes of internal state (interpreted as a LE
  uint32) after running the usual rounds added to the initial internal state
  (again, with each 4 bytes interpreted as a LE uint32).

  Therefore, we can implement HChaCha20 by:

  1. Creating the ChaCha20 initial state by concatenating the ChaCha20
    constants with the 32-byte key and the 16-byte nonce.
  2. Running ChaCha20 with the 32-byte key, 16-byte nonce, and zero-filled
    64-byte data to get 64 byte output. The zero-filled data makes the
    internal XOR operations no-ops.
  3. Read the first 16 bytes and last 16 bytes of ChaCha20 output as LE uint32s
    and subtract each corresponding LE uint32 from the initial state.
  4. Concatenate the resulting 32 bytes to produce the HChaCha20 output. */

  // create initial ChaCha20 state as 16 LE uint32s (no need to convert to
  // 64 bytes as the numbers will be used directly below)
  const state = new Array(16);
  for(let i = 0; i < 4; ++i) {
    state[i] = CHACHA20_CONSTANTS[i];
  }
  const dvKey = new DataView(key.buffer, key.byteOffset, key.length);
  for(let i = 0; i < 8; ++i) {
    state[i + 4] = dvKey.getUint32(i * 4, LE);
  }
  const dvNonce = new DataView(nonce.buffer, nonce.byteOffset, nonce.length);
  for(let i = 0; i < 4; ++i) {
    state[i + 12] = dvNonce.getUint32(i * 4, LE);
  }

  // run ChaCha20
  const dst = await _chacha20({key, nonce, src: NULL_DATA});

  // generate HChaCha20 output
  const out = new Uint8Array(32);
  const dvOut = new DataView(out.buffer, out.byteOffset, out.length);
  const dvDst = new DataView(dst.buffer, dst.byteOffset, dst.length);
  for(let i = 0; i < 4; ++i) {
    dvOut.setUint32(i * 4, (dvDst.getUint32(i * 4, LE) - state[i]) | 0, LE);
  }
  for(let i = 0; i < 4; ++i) {
    dvOut.setUint32(
      i * 4 + 16, (dvDst.getUint32(i * 4 + 48, LE) - state[i + 12]) | 0, LE);
  }

  return out;
}
