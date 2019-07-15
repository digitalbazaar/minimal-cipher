/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import {createKek} from './aeskw.js';
import * as base58 from './base58.js';
import {deriveKey} from './ecdhkdf.js';
import nacl from 'tweetnacl';
import {TextEncoder} from '../util.js';

// TODO: needs:
// 1. Decryption case: get Kek from a private key agreement key and a
//    peer's public ephemeral DH key
//    `kekFromEphemeralPeer`
//
// 2. Encryption case: get Kek *and* ephemeral DH key from a peer's public
//    static key
//    `kekFromStaticPeer`

export async function kekFromEphemeralPeer(
  {keyAgreementKey, ephemeralPublicKey}) {
  // safe to use IDs like in rfc7518 or does
  // https://tools.ietf.org/html/rfc7748#section-7 pose any issues?
  const encoder = new TextEncoder();
  const producerInfo = base58.decode(ephemeralPublicKey.publicKeyBase58);
  const consumerInfo = encoder.encode(keyAgreementKey.id);
  const secret = await keyAgreementKey.deriveSecret(
    {publicKey: ephemeralPublicKey});
  const keyData = await deriveKey({secret, producerInfo, consumerInfo});
  return {
    kek: createKek({keyData})
  };
}

export async function kekFromStaticPeer({staticPublicKey}) {
  // generate X25519 ephemeral public key
  const keyPair = nacl.box.keyPair();
  const {secretKey: privateKey} = keyPair;
  const remotePublicKey = base58.decode(staticPublicKey.publicKeyBase58);

  const encoder = new TextEncoder();
  const producerInfo = remotePublicKey;
  const consumerInfo = encoder.encode(staticPublicKey.id);
  const secret = await deriveSecret({privateKey, remotePublicKey});
  const keyData = await deriveKey({secret, producerInfo, consumerInfo});
  return {
    kek: createKek({keyData}),
    ephemeralPublicKey: keyPair.publicKey
  };
}

async function deriveSecret({privateKey, remotePublicKey}) {
  // `scalarMult` takes publicKey as param 1, secret key as param 2
  return nacl.scalarMult(remotePublicKey, privateKey);
}
