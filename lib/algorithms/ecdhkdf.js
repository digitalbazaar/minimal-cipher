/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
import crypto from '../crypto.js';

// RFC 7518 Section 4.6.2 specifies using SHA-256 for ECDH-ES KDF
// https://tools.ietf.org/html/rfc7518#section-4.6.2
const HASH_ALGORITHM = {name: 'SHA-256'};

// derived keys are always 256-bits
const KEY_LENGTH = 256;

/**
 * Derives a 256-bit AES-KW key encryption key from a shared secret that
 * was derived from an ephemeral and static pair
 * of Elliptic Curve Diffie-Hellman keys.
 *
 * The KDF used is described in RFC 7518. This KDF is referenced by RFC 8037,
 * which defines how to perform Curve25519 (X25519) ECDH key agreement.
 *
 * @param {object} options - The options to use.
 * @param {Uint8Array} options.secret - The shared secret (i.e., `Z`) to use.
 * @param {Uint8Array} options.producerInfo - An array of application-specific
 *   bytes describing the consumer (aka the "encrypter" or "sender").
 * @param {Uint8Array} options.consumerInfo - An array of application-specific
 *   bytes describing the producer (aka the "decrypter" or
 *   "receiver"/"recipient").
 * @param {string} options.alg - The algorithm name, such as ECDH-ES+256KW.
 *
 * @returns {Promise<Uint8Array>} - Resolves to the generated key.
 */
export async function deriveKey({secret, producerInfo, consumerInfo, alg}) {
  if(!(secret instanceof Uint8Array && secret.length > 0)) {
    throw new TypeError('"secret" must be a non-empty Uint8Array.');
  }

  // no extra info supplied, just hash the secret
  if(!producerInfo && !consumerInfo) {
    // hash input and return result as derived key
    return new Uint8Array(
      await crypto.subtle.digest(HASH_ALGORITHM, secret));
  }

  if(!(producerInfo instanceof Uint8Array && producerInfo.length > 0)) {
    throw new TypeError('"producerInfo" must be a non-empty Uint8Array.');
  }
  if(!(consumerInfo instanceof Uint8Array && consumerInfo.length > 0)) {
    throw new TypeError('"consumerInfo" must be a non-empty Uint8Array.');
  }

  // create algorithmID encoded buffer
  const algorithmContent = new TextEncoder().encode(alg);
  const algorithmID = new Uint8Array(4 + algorithmContent.length);
  // write length of content as 32-bit big endian integer, then write content
  const algoDV = new DataView(
    algorithmID.buffer,
    algorithmID.byteOffset,
    algorithmID.byteLength);
  algoDV.setUint32(0, algorithmContent.length);
  algorithmID.set(algorithmContent, 4);

  // the output of Concat KDF is hash(roundNumber || Z || OtherInfo)
  // where roundNumber is always 1 because the hash length is presumed to
  // ...match the key length, encoded as a big endian 32-bit integer
  // where OtherInfo is:
  // AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo
  // where SuppPubInfo is the key length in bits, big endian encoded as a
  // 32-bit number, i.e., 256 === [0, 0, 1, 0]
  const input = new Uint8Array(
    4 + // round number
    secret.length + // `Z`
    algorithmID.length + // AlgorithmID
    4 + producerInfo.length + // PartyUInfo
    4 + consumerInfo.length + // PartyVInfo
    4); // SuppPubInfo (key data length in bits)

  let offset = 0;
  const dv = new DataView(input.buffer, input.byteOffset, input.byteLength);
  dv.setUint32(offset, 1);
  input.set(secret, offset += 4);
  input.set(algorithmID, offset += secret.length);
  dv.setUint32(offset += algorithmID.length, producerInfo.length);
  input.set(producerInfo, offset += 4);
  dv.setUint32(offset += producerInfo.length, consumerInfo.length);
  input.set(consumerInfo, offset += 4);
  dv.setUint32(offset += consumerInfo.length, KEY_LENGTH);

  // hash input and return result as derived key
  return new Uint8Array(
    await crypto.subtle.digest(HASH_ALGORITHM, input));
}
