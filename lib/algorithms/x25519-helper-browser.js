/*!
 * Copyright (c) 2019-2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import crypto from '../crypto.js';
import {x25519} from '@noble/curves/ed25519';

export async function generateEphemeralKeyPair() {
  // generate X25519 ephemeral public key
  const privateKey = await crypto.getRandomValues(new Uint8Array(32));
  const publicKey = x25519.scalarMultBase(privateKey);
  return {
    privateKey,
    publicKey,
    epk: {
      kty: 'OKP',
      crv: 'X25519',
      x: base64url.encode(publicKey)
    }
  };
}

export async function deriveSecret({privateKey, remotePublicKey}) {
  // `scalarMult` takes secret key as param 1, public key as param 2
  return x25519.scalarMult(privateKey, remotePublicKey);
}
