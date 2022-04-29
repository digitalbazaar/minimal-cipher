/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
import * as base58 from 'base58-universal';
import nacl from 'tweetnacl';
import {
  deriveSecret as dhDeriveSecret,
  multibaseEncode,
  multibaseDecode,
  MULTICODEC_X25519_PUB_HEADER
} from '../lib/algorithms/x25519.js';
import {store} from './store.js';

export class KaK {
  constructor({keyPair, id = 'urn:123'} = {}) {
    this.id = id;
    this.type = 'X25519KeyAgreementKey2020';
    if(!keyPair) {
      keyPair = nacl.box.keyPair();
      this.privateKey = keyPair.secretKey;
      this.publicKey = keyPair.publicKey;
    } else {
      this.privateKey = base58.decode(keyPair.privateKeyBase58);
      this.publicKey = base58.decode(keyPair.publicKeyBase58);
    }
    this.publicKeyMultibase = multibaseEncode(
      MULTICODEC_X25519_PUB_HEADER, this.publicKey
    );

    store.set(id, this.publicKeyNode);
  }
  /**
   * Formats this KaK into an object
   * complaint with JSON-LD-Signatures.
   *
   * @returns {object} A JSON-LD object.
   */
  get publicKeyNode() {
    return {
      '@context': 'https://w3id.org/security/suites/x25519-2020/v1',
      id: this.id,
      type: this.type,
      publicKeyMultibase: this.publicKeyMultibase
    };
  }
  /**
   * Formats this Kak into a partially complete JOSE Header
   * that can be used as a recipient of a JWE.
   *
   * @returns {object} A partial JOSE header.
   */
  get recipient() {
    return {
      header: {kid: this.id, alg: 'ECDH-ES+A256KW'}
    };
  }
  async deriveSecret({publicKey}) {
    const remotePublicKey = multibaseDecode(
      MULTICODEC_X25519_PUB_HEADER, publicKey.publicKeyMultibase);

    const {privateKey} = this;
    return dhDeriveSecret({privateKey, remotePublicKey});
  }
}
