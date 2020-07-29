/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */

const nodejs = (
  typeof process !== 'undefined' && process.versions && process.versions.node);
const browser = !nodejs &&
  (typeof window !== 'undefined' || typeof self !== 'undefined');

export default {
  nodejs,
  browser
};
