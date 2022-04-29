/*!
 * Copyright (c) 2021-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {CachedResolver} from '@digitalbazaar/did-io';
import {driver as didKeyDriver} from '@digitalbazaar/did-method-key';

const resolver = new CachedResolver();

// Config did-io to support did:key driver
resolver.use(didKeyDriver());

export function createKeyResolver() {
  return async function keyResolver({id} = {}) {
    if(!id.startsWith('did:')) {
      throw new Error(`Key ID "${id}" not supported in resolver.`);
    }
    return resolver.get({did: id});
  };
}
