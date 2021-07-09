/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
const {CachedResolver} = require('@digitalbazaar/did-io');
const {driver} = require('@digitalbazaar/did-method-key');
const resolver = new CachedResolver();

// Config did-io to support did:key driver
resolver.use(driver());

function createKeyResolver() {
  return async function keyResolver({id} = {}) {
    if(!id.startsWith('did:')) {
      throw new Error(`Key ID "${id}" not supported in resolver.`);
    }
    return resolver.get({did: id});
  };
}

module.exports.createKeyResolver = createKeyResolver;
