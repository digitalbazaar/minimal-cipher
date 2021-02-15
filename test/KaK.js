/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const base58 = require('base58-universal');
const nacl = require('tweetnacl');
const {deriveSecret: dhDeriveSecret} = require('../algorithms/x25519');
const {store} = require('./store');

module.exports = class KaK {
  constructor({keyPair, id = 'urn:123'} = {}) {
    this.id = id,
    this.type = 'X25519KeyAgreementKey2019';
    if(!keyPair) {
      keyPair = nacl.box.keyPair();
      this.privateKey = keyPair.secretKey;
      this.publicKey = keyPair.publicKey;
      this.publicKeyBase58 = base58.encode(this.publicKey);
    } else {
      this.privateKey = base58.decode(keyPair.privateKeyBase58);
      this.publicKey = base58.decode(keyPair.publicKeyBase58);
      this.publicKeyBase58 = keyPair.publicKeyBase58;
    }
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
      '@context': 'https://w3id.org/security/v2',
      id: this.id,
      type: this.type,
      publicKeyBase58: this.publicKeyBase58
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
    const remotePublicKey = base58.decode(publicKey.publicKeyBase58);
    const {privateKey} = this;
    return dhDeriveSecret({privateKey, remotePublicKey});
  }
};
