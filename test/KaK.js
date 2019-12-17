const base58 = require('../base58');
const nacl = require('tweetnacl');

class KaK {
  constructor({keyPair} = {}) {
    this.id = 'urn:123',
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
  }

  async deriveSecret({publicKey}) {
    const remotePublicKey = base58.decode(publicKey.publicKeyBase58);
    return nacl.scalarMult(this.privateKey, remotePublicKey);
  }
}

module.exports = KaK;
