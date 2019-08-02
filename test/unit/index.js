const chai = require('chai');
const {Cipher} = require('../../');
const KaK = require('../KaK');
const chaiCipher = require('../chai-cipher');

chai.should();
chai.use(chaiCipher);

const cipherAlgorithms = ['recommended', 'fips'];

describe('minimal-cipher should use ', function() {
  cipherAlgorithms.forEach(algorithm => {
    describe(`the ${algorithm} algorithm`, function() {

      // each test inits data to null
      let cipher, keyAgreementKey, publicKeyNode, recipients = null;

      // keyResolver returns publicKeyNode
      const keyResolver = async () => publicKeyNode;

      beforeEach(async function() {
        cipher = new Cipher({version: algorithm});
        keyAgreementKey = new KaK();
        publicKeyNode = {
          '@context': 'https://w3id.org/security/v2',
          id: keyAgreementKey.id,
          type: keyAgreementKey.type,
          publicKeyBase58: keyAgreementKey.publicKeyBase58
        };
        recipients = [{
          header: {kid: keyAgreementKey.id, alg: 'ECDH-ES+A256KW'}
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

      it('to decrypt a simple Uint8Array', async function() {
        const data = new Uint8Array([0x01, 0x02, 0x03]);
        const jwe = await cipher.encrypt({data, recipients, keyResolver});
        jwe.should.be.a.JWE;
        const result = await cipher.decrypt({jwe, keyAgreementKey});
        result.should.deep.equal(data);
      });

      it('to decrypt a simple string', async function() {
        const data = 'simple';
        const jwe = await cipher.encrypt({data, recipients, keyResolver});
        jwe.should.be.a.JWE;
        const result = await cipher.decrypt({jwe, keyAgreementKey});
        const resultString = new TextDecoder('utf-8').decode(result);
        resultString.should.deep.equal(data);
      });

      it('to decrypt a simple object', async function() {
        const obj = {simple: true};
        const jwe = await cipher.encryptObject(
          {obj, recipients, keyResolver});
        jwe.should.be.a.JWE;
        const result = await cipher.decryptObject({jwe, keyAgreementKey});
        result.should.deep.equal(obj);
      });

    });
  });
});
