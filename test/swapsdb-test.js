/**
 *
 */

'use strict';

const SwapsDB = require('../lib/swapsdb');
const Program = require('../lib/program');
const Address = require('hsd/lib/primitives/address');
const SwapProof = require('../lib/swapproof');
const random = require('bcrypto/lib/random');
const Network = require('hsd/lib/protocol/network');
const assert = require('bsert');
const Outpoint = require('hsd/lib/primitives/outpoint');

const AddrWitness = require('../lib/addrwitness');

const network = Network.get('testnet');
let swapsdb;

describe('SwapsDB', function() {
  beforeEach(async () => {
    swapsdb = new SwapsDB({
      memory: true,
      network: network
    });

    await swapsdb.open();
  });

  afterEach(async () => {
    await swapsdb.wipe();
    await swapsdb.close();
  });

  it('should put/get tip', async () => {
    const hash = random.randomBytes(32);
    await swapsdb.putTip(hash);

    const indexed = await swapsdb.getTip();

    assert.bufferEqual(hash, indexed);
  });

  it('should put swapproof', async () => {
    const bytes = random.randomBytes(64);

    const proof = SwapProof.fromOptions({
      version: 0,
      name: 'foobar',
      program: new Program(),
      signature: bytes,
      address: new Address(),
      value: 100
    });

    assert(await swapsdb.putSwapProof('foobar', proof));
  });

  it('should get swapproof', async () => {
    const bytes = random.randomBytes(64);

    const proof = SwapProof.fromOptions({
      version: 0,
      name: 'mytest',
      program: new Program(),
      signature: bytes,
      address: new Address(),
      value: 100,
      network: network
    });

    assert(await swapsdb.putSwapProof('mytest', proof));

    const read = await swapsdb.getSwapProof('mytest');

    assert.deepEqual(proof, read);
  });

  it('should has swapproof', async () => {
    const bytes = random.randomBytes(64);

    const proof = SwapProof.fromOptions({
      version: 0,
      name: 'tester',
      program: new Program(),
      signature: bytes,
      address: new Address(),
      value: 200,
      network: network
    });

    assert(await swapsdb.putSwapProof('tester', proof));
    assert(await swapsdb.getSwapProof('tester'));
  });

  it('should delete swapproof', async () => {
    const bytes = random.randomBytes(64);

    const proof = SwapProof.fromOptions({
      version: 0,
      name: 'foobar',
      program: new Program(),
      signature: bytes,
      address: new Address(),
      value: 200,
      network: network
    });

    assert(await swapsdb.putSwapProof('foobar', proof));
    assert.equal(await swapsdb.hasSwapProof('foobar'), true);
    assert(await swapsdb.deleteSwapProof('foobar'));
    assert.equal(await swapsdb.hasSwapProof('foobar'), false);
  });

  it('should get swapproofs', async () => {
    const bytes = random.randomBytes(64);
    const size = 4;

    // create multiple proofs in loop
    // assert the proofs from the db
    for (let i = 0; i < size; i++) {
      const name = `test${i}`;

      const proof = SwapProof.fromOptions({
        version: 0,
        name: name,
        program: new Program(),
        signature: bytes,
        address: new Address(),
        value: 200,
        network: network
      });

      assert(await swapsdb.putSwapProof(proof.name, proof));
    }

    const proofs = await swapsdb.getSwapProofs();
    assert.equal(proofs.length, size);

    for (const [i, proof] of proofs.entries())
      assert.equal(proof.name, `test${i}`);
  });

  it('should put program', async () => {
    const txid = random.randomBytes(32);
    const bytes = random.randomBytes(32);
    const index = 0;

    const program = Program.fromOptions({
      type: Program.types.SCRIPT,
      data: bytes,
      outpoint: new Outpoint(txid, index)
    });

    assert(await swapsdb.putProgram(txid, index, program));
  });

  it('should get program', async () => {
    const txid = random.randomBytes(32);
    const pubkeyhash = random.randomBytes(20);
    const index = 0;

    const program = Program.fromOptions({
      type: Program.types.PUBKEY,
      data: pubkeyhash,
      outpoint: new Outpoint(txid, index)
    });

    assert(await swapsdb.putProgram(txid, index, program));

    const read = await swapsdb.getProgram(txid, index);

    assert.deepEqual(program, read);
  });

  it('should has program', async () => {
    const txid = random.randomBytes(32);
    const pubkeyhash = random.randomBytes(20);
    const index = 0;

    const program = Program.fromOptions({
      type: Program.types.PUBKEY,
      data: pubkeyhash,
      outpoint: new Outpoint(txid, index)
    });

    assert(await swapsdb.putProgram(txid, index, program));

    assert(await swapsdb.hasProgram(txid, index));
  });

  it('should delete program', async () => {
    const txid = random.randomBytes(32);
    const pubkeyhash = random.randomBytes(20);
    const index = 0;

    const program = Program.fromOptions({
      type: Program.types.PUBKEY,
      data: pubkeyhash,
      outpoint: new Outpoint(txid, index)
    });

    assert(await swapsdb.putProgram(txid, index, program));
    assert(await swapsdb.hasProgram(txid, index));
    assert(await swapsdb.deleteProgram(txid, index));
    assert.equal(await swapsdb.hasProgram(txid, index), false);
  });

  it('should get programs', async () => {
    const size = 4;

    const hashes = [];
    const outpoints = [];

    for (let i = 0; i < size; i++) {
      hashes.push(random.randomBytes(32));
      outpoints.push([random.randomBytes(32), 0]);
    }

    for (const [i, hash] of hashes.entries()) {
      const [txid, index] = outpoints[i];
      const program = Program.fromOptions({
        type: Program.types.PUBKEY,
        data: hash,
        outpoint: new Outpoint(txid, index)
      });

      assert(await swapsdb.putProgram(txid, index, program));
    }

    const programs = await swapsdb.getPrograms();

    assert.equal(programs.length, size);
  });
});
