/**
 * test/addrwitness-test.js - AddrWitness tests for NameSwaps
 */

'use strict';

const AddrWitness = require('../lib/addrwitness');
const Address = require('hsd/lib/primitives/address');
const assert = require('bsert');
const Network = require('hsd/lib/protocol/network');
const random = require('bcrypto/lib/random');
const sha3 = require('bcrypto/lib/sha3');
const network = Network.get('testnet');

describe('AddrWitness', function() {
  it('should instantiate from p2wpkh address', () => {
    const addr = 'ts1qhl0zw3mtffpk566q7dglgkn9y67myf36fnqasr';
    const witness = '025b8b459fa69d3b79ed9dfcf00d4106ba29fcd479f76259503bed702405e0cbd5';

    const addrwitness = AddrWitness.fromAddress(addr, witness);
    assert(addrwitness.isValid())
  });

  it('should instantiate from p2wsh address', () => {
    const preimage = random.randomBytes(32);
    const hash = sha3.digest(preimage);

    const addr = Address.fromScripthash(hash);

    const addrwitness = AddrWitness.fromAddress(addr, preimage);
    assert(addrwitness.isValid())
  });

  it('should fail on invalid p2wpkh (bad digest)', () => {
    const addr = 'ts1qhl0zw3mtffpk566q7dglgkn9y67myf36fnqasr';
    const witness = '025b8b459fa69d3b79ed9dfcf00d4106ba29fcd479f76259503bed702405e0cbd1';

    const addrwitness = AddrWitness.fromAddress(addr, witness);
    assert.equal(addrwitness.isValid(), false)
  });

  it('should fail on invalid p2wpkh (bad key)', () => {
    const addr = 'ts1qhl0zw3mtffpk566q7dglgkn9y67myf36fnqasr';
    const witness = '005b8b459fa69d3b79ed9dfcf00d4106ba29fcd479f76259503bed702405e0cbd5';

    const addrwitness = AddrWitness.fromAddress(addr, witness);
    assert.equal(addrwitness.isValid(), false)
  });

  it('should fail on invalid p2sh', () => {
    const preimage = random.randomBytes(32);
    const hash = sha3.digest(preimage);
    hash[0] = hash[0] ^ 1;

    const addr = Address.fromScripthash(hash);

    const addrwitness = AddrWitness.fromAddress(addr, preimage);
    assert.equal(addrwitness.isValid(), false)
  });

  it('should serialize/deserialize', () => {
    const preimage = random.randomBytes(32);
    const hash = sha3.digest(preimage);

    const addr = Address.fromScripthash(hash);
    const addrwitness = AddrWitness.fromAddress(addr, preimage, network);

    const raw = addrwitness.encode();
    assert.deepEqual(addrwitness, AddrWitness.decode(raw, {
      address: addr,
      network: network
    }));
  });

  it('should instantiate from json', () => {
    const addrwitness = AddrWitness.fromJSON({
      address: 'ts1qhl0zw3mtffpk566q7dglgkn9y67myf36fnqasr',
      witness: '025b8b459fa69d3b79ed9dfcf00d4106ba29fcd479f76259503bed702405e0cbd5'
    });

    assert(addrwitness.isValid());
  });

  it('should to json', () => {
    const addrdata = {
      address: 'ts1qhl0zw3mtffpk566q7dglgkn9y67myf36fnqasr',
      witness: '025b8b459fa69d3b79ed9dfcf00d4106ba29fcd479f76259503bed702405e0cbd5',
      type: 'PUBKEY'
    };

    const addrwitness = AddrWitness.fromJSON(addrdata);

    assert.deepEqual(addrdata, addrwitness.toJSON());
  });
});
