/*!
 * Copyright (c) 2021-2023 Digital Bazaar, Inc. All rights reserved.
 */
import {CachedResolver} from '@digitalbazaar/did-io';
import {driver} from '@digitalbazaar/did-method-key';
import {Ed25519VerificationKey2020} from
  '@digitalbazaar/ed25519-verification-key-2020';

const resolver = new CachedResolver();

// config did-io to support did:key driver
const didKeyDriver = driver();
didKeyDriver.use({
  multibaseMultikeyHeader: 'z6Mk',
  fromMultibase: Ed25519VerificationKey2020.from
});
resolver.use(didKeyDriver);

export function createKeyResolver() {
  return async function keyResolver({id} = {}) {
    if(!id.startsWith('did:')) {
      throw new Error(`Key ID "${id}" not supported in resolver.`);
    }
    return resolver.get({did: id});
  };
}
