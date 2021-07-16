/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const {CachedResolver} = require('@digitalbazaar/did-io');
const {driver: didKeyDriver} = require('@digitalbazaar/did-method-key');

const resolver = new CachedResolver();

// Config did-io to support did:key driver
resolver.use(didKeyDriver());

function createKeyResolver() {
  return async function keyResolver({id} = {}) {
    if(!id.startsWith('did:')) {
      throw new Error(`Key ID "${id}" not supported in resolver.`);
    }
    return resolver.get({did: id});
  };
}

module.exports.createKeyResolver = createKeyResolver;
