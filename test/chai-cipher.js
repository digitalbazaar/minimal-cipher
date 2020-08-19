/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

module.exports = function(chai) {
  const {Assertion} = chai;
  Assertion.addProperty('JWE', function() {
    const jwe = this._obj;
    new Assertion(jwe).to.be.an('object');
    new Assertion(jwe.protected).to.exist;
    new Assertion(jwe.protected).to.be.a(
      'string', 'Expected the property protected to be a string.');
    new Assertion(jwe.recipients).to.exist;
    new Assertion(jwe.recipients).to.be.an(
      'array', 'Expected JWE recipients to be an array.');
    new Assertion(jwe.iv).to.exist;
    new Assertion(jwe.iv).to.be.a(
      'string', 'Expected JWE Initialization Vector to be a string.');
    new Assertion(jwe.ciphertext).to.exist;
    new Assertion(jwe.ciphertext).to.be.a(
      'string', 'Expected JWE ciphertext to be a string.');
    new Assertion(jwe.tag).to.exist;
    new Assertion(jwe.tag).to.be.a(
      'string', 'Expected JWE tag to be a string');
  });
};
