/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
import base64url from 'base64url-universal';
import {createKek} from './aeskw.js';
import * as base58 from 'base58-universal';
import {deriveKey} from './ecdhkdf.js';
import nacl from 'tweetnacl';
import {TextEncoder} from '../util.js';
import env from '../env.js';

const PUBLIC_KEY_DER_PREFIX = new Uint8Array([
  48, 42, 48, 5, 6, 3, 43, 101, 110, 3, 33, 0
]);

const PRIVATE_KEY_DER_PREFIX = new Uint8Array([
  48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32
]);

const KEY_TYPE = 'X25519KeyAgreementKey2019';

export const JWE_ALG = 'ECDH-ES+A256KW';

export async function deriveEphemeralKeyPair() {
  // generate X25519 ephemeral public key
  let keyPair;
  if(await _hasNodeDiffieHellman()) {
    const crypto = await import('crypto');
    const {promisify} = await import('util');
    const generateKeyPairAsync = promisify(crypto.generateKeyPair);
    const publicKeyEncoding = {format: 'der', type: 'spki'};
    const privateKeyEncoding = {format: 'der', type: 'pkcs8'};
    const {publicKey: publicDerBytes, privateKey: privateDerBytes} =
      await generateKeyPairAsync('x25519', {
        publicKeyEncoding, privateKeyEncoding
      });
    const publicKey = publicDerBytes.slice(12, 12 + 32);
    const secretKey = privateDerBytes.slice(16, 16 + 32);
    keyPair = {secretKey, publicKey};
  } else {
    keyPair = nacl.box.keyPair();
  }
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

// Decryption case: get Kek from a private key agreement key and a
// peer's public ephemeral DH key encoded as an `epk`
export async function kekFromEphemeralPeer({keyAgreementKey, epk}) {
  if(!(epk && typeof epk === 'object')) {
    throw new TypeError('"epk" must be an object.');
  }
  if(epk.kty !== 'OKP') {
    throw new Error('"epk.kty" must be the string "OKP".');
  }
  if(epk.crv !== 'X25519') {
    throw new Error('"epk.crv" must be the string "X25519".');
  }
  // decode public key material
  const publicKey = base64url.decode(epk.x);

  // convert to LD key for Web KMS
  const ephemeralPublicKey = {
    type: KEY_TYPE,
    publicKeyBase58: base58.encode(publicKey)
  };

  // safe to use IDs like in rfc7518 or does
  // https://tools.ietf.org/html/rfc7748#section-7 pose any issues?
  const encoder = new TextEncoder();
  // "Party U Info"
  const producerInfo = publicKey;
  // "Party V Info"
  const consumerInfo = encoder.encode(keyAgreementKey.id);
  const secret = await keyAgreementKey.deriveSecret(
    {publicKey: ephemeralPublicKey});
  const keyData = await deriveKey({secret, producerInfo, consumerInfo});
  return {
    kek: await createKek({keyData})
  };
}

// Encryption case: get Kek *and* ephemeral DH key from a peer's public
// static key
export async function kekFromStaticPeer({ephemeralKeyPair, staticPublicKey}) {
  const {privateKey} = ephemeralKeyPair;
  // TODO: consider accepting JWK format for `staticPublicKey` not just LD key
  if(staticPublicKey.type !== KEY_TYPE) {
    throw new Error(
      `"staticPublicKey.type" must be "${KEY_TYPE}".`);
  }
  const remotePublicKey = base58.decode(staticPublicKey.publicKeyBase58);

  const encoder = new TextEncoder();
  // "Party U Info"
  const producerInfo = ephemeralKeyPair.publicKey;
  // "Party V Info"
  const consumerInfo = encoder.encode(staticPublicKey.id);
  const secret = await deriveSecret({privateKey, remotePublicKey});
  const keyData = await deriveKey({secret, producerInfo, consumerInfo});
  return {
    kek: await createKek({keyData}),
    epk: ephemeralKeyPair.epk,
    apu: base64url.encode(producerInfo),
    apv: base64url.encode(consumerInfo),
    ephemeralPublicKey: ephemeralKeyPair.publicKey
  };
}

async function deriveSecret({privateKey, remotePublicKey}) {
  if(await _hasNodeDiffieHellman()) {
    const crypto = await import('crypto');
    const nodePrivateKey = crypto.createPrivateKey({
      key: Buffer.concat([PRIVATE_KEY_DER_PREFIX, privateKey]),
      format: 'der',
      type: 'pkcs8'
    });
    const nodePublicKey = crypto.createPublicKey({
      key: Buffer.concat([PUBLIC_KEY_DER_PREFIX, remotePublicKey]),
      format: 'der',
      type: 'spki'
    });
    return crypto.diffieHellman({
      privateKey: nodePrivateKey,
      publicKey: nodePublicKey,
    });
  }

  // `scalarMult` takes secret key as param 1, public key as param 2
  return nacl.scalarMult(privateKey, remotePublicKey);
}

async function _hasNodeDiffieHellman() {
  // crypto.diffieHellman was added in Node.js v13.9.0
  return (env.nodejs && (await import('crypto')).diffieHellman);
}
