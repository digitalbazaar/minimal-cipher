const {Cipher} = require('../../index');
const base58 = require('../base58esm');

const cipherAlgorithms = ['recommended', 'fips'];

describe('minimal-cipher should use ', function() {
  cipherAlgorithms.forEach(algorithm => {
    describe(`the ${algorithm} algorithm`, function() {
      let cipher, keyPair, publicKeyNode = null;
      const keyResolver = async () => publicKeyNode
      beforeEach(async function() {
        cipher = new Cipher({version: algorithm});
        keyPair = await cipher.keyAgreement.deriveEphemeralKeyPair();
        publicKeyNode = {
          '@context': 'https://w3id.org/security/v2',
          id: 'urn:123',
          type: 'X25519KeyAgreementKey2019',
          publicKeyBase58: base58.encode(keyPair.publicKey)
        };
      });
      it('to encrypt some simple bites', async function() {
        const data = new Uint8Array([0x01, 0x02, 0x03]);
        const recipients = [{
          header: {kid: publicKeyNode.id}
        }];
        const result = await cipher.encrypt({data, recipients, keyResolver});
        console.log(result);
      });
      it('to encrypt a stream', async function() {

      });
    });
  });
});
