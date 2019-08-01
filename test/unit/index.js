const chai = require('chai');
const {Cipher} = require('../../index');
const base58 = require('../base58esm');
const chaiCipher = require('../chai-cipher');
chai.should();
chai.use(chaiCipher);

const cipherAlgorithms = ['recommended', 'fips'];

describe('minimal-cipher should use ', function() {
  cipherAlgorithms.forEach(algorithm => {
    describe(`the ${algorithm} algorithm`, function() {

      // each test inits data to null
      let cipher, keyPair, publicKeyNode, recipients = null;

      // keyResolver returns publicKeyNode
      const keyResolver = async () => publicKeyNode;

      beforeEach(async function() {
        cipher = new Cipher({version: algorithm});
        keyPair = await cipher.keyAgreement.deriveEphemeralKeyPair();
        publicKeyNode = {
          '@context': 'https://w3id.org/security/v2',
          id: 'urn:123',
          type: 'X25519KeyAgreementKey2019',
          publicKeyBase58: base58.encode(keyPair.publicKey)
        };
        recipients = [{
          header: {kid: publicKeyNode.id, alg: 'ECDH-ES+A256KW'}
        }];
      });

      it('to encrypt a simple Uint8Array', async function() {
        const data = new Uint8Array([0x01, 0x02, 0x03]);
        const result = await cipher.encrypt({data, recipients, keyResolver});
        result.should.be.a.JWE;
      });

      it('to encrypt a simple string', async function() {
        const data = 'simple';
        const result = await cipher.encrypt({data, recipients, keyResolver});
        result.should.be.a.JWE;
      });

      it('to encrypt a simple object', async function() {
        const obj = {simple: true};
        const result = await cipher.encryptObject(
          {obj, recipients, keyResolver});
        result.should.be.a.JWE;
      });

      it.skip('to encrypt a stream', async function() {

      });

    });
  });
});
