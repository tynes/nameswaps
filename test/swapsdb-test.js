/**
 *
 */

'use strict';

const SwapsDB = require('../lib/swapsdb');
const AddrWitness = require('../lib/addrwitness');
const random = require('bcrypto/lib/random');
const Network = require('hsd/lib/protocol/network');
const assert = require('bsert');

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

  it('should put addrwitness', async () => {
    const addr = 'ts1qhl0zw3mtffpk566q7dglgkn9y67myf36fnqasr';
    const witness = '025b8b459fa69d3b79ed9dfcf00d4106ba29fcd479f76259503bed702405e0cbd5';

    const addrwitness = AddrWitness.fromAddress(addr, witness);
    await swapsdb.putAddrWitness(addrwitness);

    const address = addrwitness.getAddress();
    assert(await swapsdb.hasAddrWitness(address));
  });

  it('should get addrwitness', async () => {
    const addr = 'ts1qhl0zw3mtffpk566q7dglgkn9y67myf36fnqasr';
    const witness = '025b8b459fa69d3b79ed9dfcf00d4106ba29fcd479f76259503bed702405e0cbd5';

    const addrwitness = AddrWitness.fromAddress(addr, witness);
    await swapsdb.putAddrWitness(addrwitness);

    const address = addrwitness.getAddress();
    const indexed = await swapsdb.getAddrWitness(address);

    assert.deepEqual(addrwitness, indexed);
  });

  it('should delete addrwitness', async () => {
    const addr = 'ts1qhl0zw3mtffpk566q7dglgkn9y67myf36fnqasr';
    const witness = '025b8b459fa69d3b79ed9dfcf00d4106ba29fcd479f76259503bed702405e0cbd5';

    const addrwitness = AddrWitness.fromAddress(addr, witness);
    const address = addrwitness.getAddress();

    await swapsdb.putAddrWitness(addrwitness);
    assert(await swapsdb.hasAddrWitness(address));

    await swapsdb.deleteAddrWitness(address);
    assert.equal(await swapsdb.hasAddrWitness(address), false);
  });
});
