/**
 * test/swapproof-test.js - SwapProof tests for NameSwaps
 */
const SwapProof = require('../lib/swapproof');
const Program = require('../lib/program');
const Address = require('hsd/lib/primitives/address');
const random = require('bcrypto/lib/random');
const assert = require('bsert');

describe('SwapProof', function() {
  it('should instantiate from options', () => {
    const bytes = random.randomBytes(64);

    const proof = SwapProof.fromOptions({
      version: 0,
      name: 'foobar',
      program: new Program(),
      signature: bytes,
      address: new Address(),
      value: 100
    });

    assert.strictEqual(proof.version, 0);
    assert.strictEqual(proof.name, 'foobar');
    assert.deepEqual(proof.program, new Program());
    assert.bufferEqual(proof.signature, bytes);
    assert.deepEqual(proof.value, 100);
  });

  it('should encode/decode', () => {
    const bytes = random.randomBytes(64);

    const proof = SwapProof.fromOptions({
      version: 1,
      name: 'testing',
      program: new Program(),
      signature: bytes,
      address: new Address(),
      value: 1000
    });

    const raw = proof.encode();
    const encoded = SwapProof.decode(raw);

    assert.strictEqual(proof.version, 1);
    assert.strictEqual(proof.name, 'testing');
    assert.deepEqual(proof.program, new Program());
    assert.bufferEqual(proof.signature, bytes);
    assert.deepEqual(proof.value, 1000);
  });

  it('should to/from json', () => {
    const json = {
      version: 0,
      name: 'test2',
      program: {
        type: 'PUBKEY',
        data: '1111',
        outpoint: {
          hash: Buffer.alloc(32).toString('hex'),
          index: 1
        }
      },
      signature: '0000',
      address: 'ts1qhl0zw3mtffpk566q7dglgkn9y67myf36fnqasr',
      value: 10,
      network: 'testnet'
    };

    const proof = SwapProof.fromJSON(json);

    // hack
    delete json.network;
    assert.deepEqual(json, proof.toJSON());
  });

  it('should verify', () => {
    this.skip();
  });
});
