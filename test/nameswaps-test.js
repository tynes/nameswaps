/**
 *
 */

'use strict';

const NameSwaps = require('../lib/nameswaps');
const AddrWitness = require('../lib/addrwitness');
const Network = require('hsd/lib/protocol/network');
const Chain = require('hsd/lib/blockchain/chain')
const assert = require('bsert');

// TODO: fix all of these tests

const network = Network.get('regtest');
let nameswaps, chain;

describe('NameSwaps', function() {
  beforeEach(async () => {
    chain = new Chain({
      network: network
    });

    nameswaps = new NameSwaps({
      network: network,
      chain: chain,
      memory: true
    });

    nameswaps.on('error', (error) => {
      assert(false);
    });

    await nameswaps.open();
  });

  afterEach(async () => {
    await nameswaps.close();
  });

  it('should index an AddrWitness', async () => {
    const addr = 'rs1qwkhw6hw3na3wf7fdvmlyrnx5r3rku2lufv56ma';
    const witness = '026ef4e01f8f6cf21db07b85dd62f5bb54af40fb6aa6ff68327013afc3ad56daec';

    assert(await nameswaps.putAddrWitness(addr, witness));
    assert(await nameswaps.hasAddrWitness(addr));
  });

  it('should index an address and witness', async () => {
    const addr = 'rs1qwkhw6hw3na3wf7fdvmlyrnx5r3rku2lufv56ma';
    const witness = '026ef4e01f8f6cf21db07b85dd62f5bb54af40fb6aa6ff68327013afc3ad56daec';

    assert(await nameswaps.putAddrWitness(addr, witness));
    assert(await nameswaps.hasAddrWitness(addr));
  });

  it('should get an address witness', async () => {
    const addr = 'rs1qwkhw6hw3na3wf7fdvmlyrnx5r3rku2lufv56ma';
    const witness = '026ef4e01f8f6cf21db07b85dd62f5bb54af40fb6aa6ff68327013afc3ad56daec';

    assert(await nameswaps.putAddrWitness(addr, witness));

    const addrwitness = await nameswaps.getAddrWitness(addr);

    const json = addrwitness.toJSON();
    assert.equal(json.witness, witness);
    assert.equal(json.address, addr);
  });

  it('should not index an invalid address witness', async () => {
    const addr = 'rs1qwkhw6hw3na3wf7fdvmlyrnx5r3rku2lufv56ma';
    const witness = '006ef4e01f8f6cf21db07b85dd62f5bb54af40fb6aa6ff68327013afc3ad56daec';

    assert.rejects(nameswaps.putAddrWitness(addr, witness), 'Invalid Witness.');
  });

  it('should delete an address witness', async () => {
    const addr = 'rs1qwkhw6hw3na3wf7fdvmlyrnx5r3rku2lufv56ma';
    const witness = '026ef4e01f8f6cf21db07b85dd62f5bb54af40fb6aa6ff68327013afc3ad56daec';

    assert(await nameswaps.putAddrWitness(addr, witness));
    assert(await nameswaps.hasAddrWitness(addr));

    assert(await nameswaps.deleteAddrWitness(addr));
    assert.equal(await nameswaps.hasAddrWitness(addr), false);
  });
});
