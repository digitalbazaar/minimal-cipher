/*!
 * Copyright (c) 2019-2023 Digital Bazaar, Inc. All rights reserved.
 */
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import {store} from './store.js';

export class FipsKak {
  constructor({id, keyPair} = {}) {
    this.id = id;
    this.type = 'Multikey';
    this.privateKey = keyPair.secretKey || keyPair.privateKey;
    this.publicKey = keyPair.publicKey;
    this.publicKeyMultibase = keyPair.publicKeyMultibase;
    this._keyPair = keyPair;
  }

  static async generate({id = 'urn:123'} = {}) {
    const keyPair = await EcdsaMultikey.generate(
      {id, curve: 'P-256', keyAgreement: true});
    const kak = new FipsKak({id, keyPair});
    store.set(id, await kak.export());
    return kak;
  }

  /**
   * Formats this Kak into an object.
   *
   * @returns {object} A JSON-LD object.
   */
  async export() {
    return this._keyPair.export({publicKey: true, includeContext: true});
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
    return this._keyPair.deriveSecret({remotePublicKey: publicKey});
  }
}
