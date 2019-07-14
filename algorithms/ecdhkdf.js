/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import crypto from '../crypto.js';
import {TextEncoder} from '../util.js';

// only supported algorithm
const KEY_ALGORITHM = 'ECDH-ES+A256KW';

// create static ALGORITHM_ID
const ALGORITHM_CONTENT = new TextEncoder().encode(KEY_ALGORITHM);
const ALGORITHM_ID = new Uint8Array(4 + ALGORITHM_CONTENT.length);
// write length of content as 32-bite big endian integer, then write content
ALGORITHM_ID.setUint32(0, ALGORITHM_CONTENT.length);
ALGORITHM_ID.set(4, ALGORITHM_CONTENT);

// RFC 7518 Section 4.6.2 specifies using SHA-256 for ECDH-ES KDF
// https://tools.ietf.org/html/rfc7518#section-4.6.2
const HASH_ALGORITHM = {name: 'SHA-256'};

// derived keys are always 256-bits
const KEY_LENGTH = 256;

/**
 * Derives a 256-bit AES-KW key encryption key from a shared secret that
 * was derived from an ephemeral and static pair of Elliptic Curve
 * Diffie-Hellman keys.
 *
 * The KDF used is described in RFC 7518. This KDF is referenced by RFC 8037,
 * which defines how to perform Curve25519 (X25519) ECDH key agreement.
 *
 * @param {Uint8Array} secret the shared secret (i.e., `Z`) to use.
 * @param {Uint8Array} consumerInfo an array of application-specific bytes
 *   describing the consumer (aka the "encrypter" or "sender").
 * @param {Uint8Array} producerInfo an array of application-specific bytes
 *   describing the producer (aka the "decrypter" or "receiver"/"recipient").
 *
 * @return {Promise<Uint8Array>} resolves to the generated key.
 */
export async function deriveKey({secret, producerInfo, consumerInfo}) {
  if(!(secret instanceof Uint8Array)) {
    throw new TypeError('"secret" must be a Uint8Array.');
  }
  if(!(producerInfo instanceof Uint8Array)) {
    throw new TypeError('"secret" must be a Uint8Array.');
  }
  if(!(consumerInfo instanceof Uint8Array)) {
    throw new TypeError('"secret" must be a Uint8Array.');
  }

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
    ALGORITHM_ID.length + // AlgorithmID
    4 + producerInfo.length + // PartyUInfo
    4 + consumerInfo.length + // PartyVInfo
    4); // SuppPubInfo (key data length in bits)

  let offset = 0;
  input.setUint32(0, 1);
  input.set(offset += 4, secret);
  input.set(offset += secret.length, ALGORITHM_ID);
  input.setUint32(offset += ALGORITHM_ID.length, producerInfo.length);
  input.set(offset += 4, producerInfo.length);
  input.setUint32(offset += producerInfo.length, consumerInfo.length);
  input.set(offset += 4, consumerInfo.length);
  input.set(offset += 4, KEY_LENGTH);

  // hash input and return result as derived key
  return new Uint8Array(
    await crypto.subtle.digest(HASH_ALGORITHM, input));
}
