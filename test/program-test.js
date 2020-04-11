/**
 * test/swapproof-test.js - SwapProof tests for NameSwaps
 */
const Program = require('../lib/primitives/program');
const SwapRing = require('../lib/wallet/swapring');
const Address = require('hsd/lib/primitives/address');
const Outpoint = require('hsd/lib/primitives/outpoint');
const random = require('bcrypto/lib/random');
const assert = require('bsert');

// TODO: add tests for validation of programs
// based on type

describe('Program', function() {
  it('should instantiate from options', () => {
    const bytes = random.randomBytes(33);

    const program = Program.fromOptions({
      type: Program.types.PUBKEY,
      data: bytes,
      outpoint: new Outpoint()
    });

    assert.strictEqual(program.type, Program.types.PUBKEY);
    assert.bufferEqual(program.data, bytes);
    assert.deepEqual(program.outpoint, new Outpoint());
  });

  it('should encode/decode', () => {
    const bytes = random.randomBytes(33);
    const outpoint = new Outpoint();

    const program = Program.fromOptions({
      type: Program.types.PUBKEY,
      data: bytes,
      outpoint: outpoint
    });

    const raw = program.encode();
    const decoded = Program.decode(raw, {
      hash: outpoint.hash,
      index: outpoint.index
    });

    assert.strictEqual(program.type, decoded.type);
    assert.bufferEqual(program.data, decoded.data);
    assert.deepEqual(program.outpoint, decoded.outpoint);
  });

  it('should encode/decode (p2p serialization)', () => {
    this.skip();

    const bytes = random.randomBytes(32);
    const txid = random.randomBytes(32);
    const index = 2;

    const program = Program.fromOptions({
      type: Program.types.SCRIPT,
      data: bytes,
      outpoint: new Outpoint(txid, index)
    });

    const raw = program.encode(true);
    const decoded = Program.decode(raw, {txid, index});

    assert.strictEqual(program.type, decoded.type);
    assert.bufferEqual(program.data, decoded.data);
    assert.deepEqual(program.outpoint, decoded.outpoint);
  });

  it('should to/from json', () => {
    const json = {
      type: 'SCRIPT',
      data: '0000',
      outpoint: {
        hash: Buffer.alloc(32).toString('hex'),
        index: 0
      }
    };

    const program = Program.fromJSON(json);
    assert.deepEqual(json, program.toJSON());
  });

  it('should work with NAIVE swap script', () => {
    this.skip();

    const ring = SwapRing.generate();

    const program = Program.fromOptions({
      type: Program.types.SCRIPT,
      data: ring.script.encode(),
      outpoint: new Outpoint()
    });

    console.log(program);
  });
});
