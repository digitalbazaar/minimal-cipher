/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {streamXOR} from '@stablelib/chacha';

// internal function exported for reuse by XChaCha20Poly1305
export function chacha20({key, nonce, src, dst}) {
  // FIXME: use node.js native implementation

  // encrypt a single block (1 == full nonce will be used no counter generated)
  try {
    // `nonce` is modified internally, so copy it first
    nonce = Uint8Array.prototype.slice.call(nonce);
    return streamXOR(key, nonce, src, dst, 1);
  } catch(e) {
    // ignore counter overflow error; we don't use the counter
    if(e.message.includes('counter overflow')) {
      return dst;
    }
    throw e;
  }
}
