/**
 *
 */

'use strict';

const assert = require('bsert');
const random = require('bcrypto/lib/random');
const Outpoint = require('hsd/lib/primitives/outpoint');
const Network = require('hsd/lib/protocol/network');
const Address = require('hsd/lib/primitives/address');
const Chain = require('hsd/lib/blockchain/chain')
const NameSwaps = require('../lib/core/nameswaps');
const Program = require('../lib/primitives/program');
const SwapProof = require('../lib/primitives/swapproof');

const network = Network.get('regtest');
let nameswaps, chain;

describe('NameSwaps', function() {
  beforeEach(async () => {
    chain = new Chain({
      network: network,
      memory: true
    });

    nameswaps = new NameSwaps({
      network: network,
      chain: chain,
      memory: true
    });

    nameswaps.on('error', (error) => {
      console.log(error);
      assert(false);
    });

    await nameswaps.open();
  });

  afterEach(async () => {
    await nameswaps.close();
  });

  it('should index a program', async () => {
    const bytes = random.randomBytes(33);
    const hash = random.randomBytes(32);
    const index = 0;

    const program = Program.fromOptions({
      type: Program.types.PUBKEY,
      data: bytes,
      outpoint: new Outpoint(hash, index)
    });

    assert(await nameswaps.putProgram(program));
  });

  it('should get a program', async () => {
    const bytes = random.randomBytes(33);
    const hash = random.randomBytes(32);
    const index = 0;

    const program = Program.fromOptions({
      type: Program.types.PUBKEY,
      data: bytes,
      outpoint: new Outpoint(hash, index)
    });

    assert(await nameswaps.putProgram(program));

    const indexed = await nameswaps.getProgram(hash, index);

    assert.deepEqual(program, indexed);
  });

  it('should get all programs', async () => {
    const programs = [];

    for (let i = 0; i < 3; i++) {
      const program = Program.fromOptions({
        type: Program.types.PUBKEY,
        data: random.randomBytes(33),
        outpoint: new Outpoint(random.randomBytes(32), i)
      });

      programs.push(program);
      assert(await nameswaps.putProgram(program));
    }

    const indexed = await nameswaps.getPrograms();

    assert.equal(programs.length, indexed.length);

    for (let i = 0; i < 3; i++) {
      const pre = programs.find(p => p.outpoint.index === i);
      const post = indexed.find(p => p.outpoint.index === i);
      assert.deepEqual(pre, post);
      assert.bufferEqual(pre.encode(), post.encode());
    }
  });

  it('should not index an invalid program', async () => {
    this.skip();
  });

  it('should check for program utxo', async () => {
    // TODO: requires adding a block to the chain
    // that includes a tx
    this.skip();

    const hash = Buffer.alloc(0);
    const index = 0;

    const hasCoin = await nameswaps.hasCoin(hash, index);
  })

  it('should has program', async () => {
    const bytes = random.randomBytes(33);
    const hash = random.randomBytes(32);
    const index = 0;

    const program = Program.fromOptions({
      type: Program.types.PUBKEY,
      data: bytes,
      outpoint: new Outpoint(hash, index)
    });

    assert(await nameswaps.putProgram(program));

    const has = await nameswaps.hasProgram(program);
    assert.equal(has, true);
  });

  it('should delete a program', async () => {
    this.skip();

    const bytes = random.randomBytes(33);
    const hash = random.randomBytes(32);
    const index = 0;

    const program = Program.fromOptions({
      type: Program.types.PUBKEY,
      data: bytes,
      outpoint: new Outpoint(hash, index)
    });

    assert(await nameswaps.putProgram(program));
    assert(await nameswaps.hasProgram(program));

    // TODO: this should only accept the key
    assert(await nameswaps.deleteProgram(program));

    const has = await nameswaps.hasProgram(program);
    assert.equal(has, false);
  });

  it('should index program outpoints by block hash', async () => {
    const hash = random.randomBytes(32);

    const program = Program.fromOptions({
      type: Program.types.PUBKEY,
      data: random.randomBytes(33),
      outpoint: new Outpoint(random.randomBytes(32), 0)
    });

    assert(await nameswaps.putProgramOutpointByBlock(hash, program));
  });

  it('should get programs by block hash', async () => {
    // First index the programs
    const programs = [];

    for (let i = 0; i < 3; i++) {
      const program = Program.fromOptions({
        type: Program.types.PUBKEY,
        data: random.randomBytes(33),
        outpoint: new Outpoint(random.randomBytes(32), i)
      });

      programs.push(program);
      assert(await nameswaps.putProgram(program));
    }

    // Then index outpoints by block hash
    const hash = random.randomBytes(32);
    for (const program of programs) {
      const {outpoint} = program;
      assert(await nameswaps.putProgramOutpointByBlock(hash, program));
    }

    // Then get programs by block hash
    const indexed = await nameswaps.getProgramsByBlock(hash);
    assert.equal(programs.length, indexed.length);

    for (let i = 0; i < 3; i++) {
      const pre = programs.find(p => p.outpoint.index === i);
      const post = indexed.find(p => p.outpoint.index === i);
      assert.deepEqual(pre, post);
      assert.bufferEqual(pre.encode(), post.encode());
    }
  });

  it('should index a swap proof', async () => {
    const bytes = random.randomBytes(64);

    const proof = SwapProof.fromOptions({
      version: 0,
      name: 'foobar',
      program: new Program(),
      signature: bytes,
      address: new Address(),
      value: 100
    });

    assert(await nameswaps.putSwapProof(proof));
  });

  it('should get a swap proof', async () => {
    const bytes = random.randomBytes(64);

    const proof = SwapProof.fromOptions({
      version: 0,
      name: 'thisisnotatest',
      program: new Program(),
      signature: bytes,
      address: new Address(),
      value: 100000,
      network: network
    });

    assert(await nameswaps.putSwapProof(proof));

    const indexed = await nameswaps.getSwapProof(proof.name);
    assert.deepEqual(proof, indexed);
  });

  it('should get all swap proofs', async () => {
    const proofs = [];

    for (let i = 0; i < 3; i++) {
      const proof = SwapProof.fromOptions({
        version: 0,
        name: i.toString(),
        program: new Program(),
        signature: random.randomBytes(64),
        address: new Address(),
        value: 100000,
        network: network
      });

      assert(await nameswaps.putSwapProof(proof));
      proofs.push(proof);
    }

    const indexed = await nameswaps.getSwapProofs();

    assert.equal(proofs.length, indexed.length);

    for (let i = 0; i < 3; i++) {
      const pre = proofs.find(p => p.name === i.toString());
      const post = indexed.find(p => p.name === i.toString());
      assert.deepEqual(pre, post);
      assert.bufferEqual(pre.encode(), post.encode());
    }
  });

  it('should not index an invalid swap proof', async () => {
    this.skip();
  });

  it('should check for swap proof utxo', async () => {
    this.skip();
  })

  it('should has a swap proof', async () => {
    const bytes = random.randomBytes(64);

    const proof = SwapProof.fromOptions({
      version: 0,
      name: 'thisisnotatest',
      program: new Program(),
      signature: bytes,
      address: new Address(),
      value: 100000,
      network: network
    });

    assert(await nameswaps.putSwapProof(proof));

    const has = await nameswaps.hasSwapProof(proof.name);
    assert.equal(has, true);
  });

  it('should delete a program', async () => {
    const proof = SwapProof.fromOptions({
      version: 0,
      name: 'thisisnotatest',
      program: new Program(),
      signature: random.randomBytes(64),
      address: new Address(),
      value: 100000,
      network: network
    });

    assert(await nameswaps.putSwapProof(proof));
    assert(await nameswaps.hasSwapProof(proof.name));

    assert(await nameswaps.deleteSwapProof(proof.name));

    const has = await nameswaps.hasSwapProof(proof.name);
    assert.equal(has, false);
  });

  it('should index programs by block hash', async () => {
    this.skip();
  });

  it('should get swap proofs by block hash', async () => {
    // First index the proofs
    const proofs = [];

    for (let i = 0; i < 3; i++) {
      const proof = SwapProof.fromOptions({
        version: 0,
        name: i.toString(),
        program: new Program(),
        signature: random.randomBytes(64),
        address: new Address(),
        value: 100000,
        network: network
      });

      assert(await nameswaps.putSwapProof(proof));
      proofs.push(proof);
    }

    // Then index outpoints by block hash
    const hash = random.randomBytes(32);
    for (const proof of proofs) {
      const {name} = proof;
      assert(await nameswaps.putSwapProofNameByBlock(hash, name));
    }

    // Then get proofs by block hash
    const indexed = await nameswaps.getSwapProofsByBlock(hash);
    assert.equal(proofs.length, indexed.length);

    for (let i = 0; i < 3; i++) {
      const pre = proofs.find(p => p.name === i.toString());
      const post = indexed.find(p => p.name === i.toString());
      assert.deepEqual(pre, post);
      assert.bufferEqual(pre.encode(), post.encode());
    }
  });
});
