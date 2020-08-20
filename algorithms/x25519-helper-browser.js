/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
import base64url from 'base64url-universal';
import nacl from 'tweetnacl';

export async function deriveEphemeralKeyPair() {
  // generate X25519 ephemeral public key
  const keyPair = nacl.box.keyPair();
  const {secretKey: privateKey, publicKey} = keyPair;
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
  return nacl.scalarMult(privateKey, remotePublicKey);
}
