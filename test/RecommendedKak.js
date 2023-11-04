/*!
 * Copyright (c) 2019-2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as base58 from 'base58-universal';
import {
  deriveSecret as dhDeriveSecret,
  multibaseDecode,
  multibaseEncode,
  MULTICODEC_X25519_PUB_HEADER
} from '../lib/algorithms/x25519.js';
import nacl from 'tweetnacl';
import {store} from './store.js';

export class RecommendedKak {
  constructor({id, keyPair} = {}) {
    this.id = id;
    this.type = 'X25519KeyAgreementKey2020';
    this.privateKey = keyPair.secretKey || keyPair.privateKey;
    this.publicKey = keyPair.publicKey;
    this.publicKeyMultibase = keyPair.publicKeyMultibase ||
      multibaseEncode(MULTICODEC_X25519_PUB_HEADER, this.publicKey);
  }

  static async generate({id = 'urn:123', legacyKeyPair} = {}) {
    let keyPair;
    if(legacyKeyPair) {
      keyPair = {
        privateKey: base58.decode(legacyKeyPair.privateKeyBase58),
        publicKey: base58.decode(legacyKeyPair.publicKeyBase58)
      };
    } else {
      // use `tweetnacl` lib to cross-compare X25519 implementations
      keyPair = nacl.box.keyPair();
    }
    const kak = new RecommendedKak({id, keyPair});
    store.set(id, await kak.export());
    return kak;
  }

  /**
   * Formats this Kak into an object.
   *
   * @returns {object} A JSON-LD object.
   */
  async export() {
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
