/**
 *
 */

const assert = require('bsert');
const SwapRing = require('../lib/wallet/swapring');
const SwapProof = require('../lib/primitives/swapproof');
const Program = require('../lib/primitives/program');
const Scripts = require('../lib/wallet/scripts');
const Coin = require('hsd/lib/primitives/coin');
const Outpoint = require('hsd/lib/primitives/outpoint');
const secp256k1 = require('bcrypto/lib/secp256k1');
const Address = require('hsd/lib/primitives/address');

describe('SwapRing', function() {
  it('should from options', () => {
    const ring = SwapRing.fromOptions({
      type: Scripts.types.NAIVE
    });

    assert.equal(ring.type, Scripts.types.NAIVE);
  });

  it('should generate', () => {
    const ring = SwapRing.generate();

    assert(secp256k1.privateKeyVerify(ring.privateKey));
    assert(secp256k1.publicKeyVerify(ring.publicKey));
  });

  it('should template', () => {
    const ring = SwapRing.generate(Scripts.types.NAIVE);
    const template = Scripts.templatesByType[Scripts.types.NAIVE];
    const script = template(ring.publicKey);
    assert.bufferEqual(ring.script.encode(), script.encode());
  });

  it('should sign and verify', () => {
    const ring = SwapRing.generate();
    const value = 1000;

    const coin = Coin.fromOptions({
      address: ring.toAddress(),
      value: value
    });

    const address = new Address();

    const signature = ring.sign({
      coin: coin,
      value: value,
      address: address
    });

    const witness = ring.toWitness({
      signature: signature,
      publicKey: ring.publicKey
    });

    const valid = ring.verify({
      coin: coin,
      value: value,
      address: address,
      signature: signature
    });

    assert(valid);
  });

  it('should verify without private key', () => {
    // Alice's ring
    const ring = SwapRing.generate();
    const value = 1000;

    // She already spent the uxto to the secure
    // script, now is consuming it.
    const coin = Coin.fromOptions({
      address: ring.toAddress(),
      value: value
    });

    // Alice address
    const address = new Address();

    // Alice signature
    const signature = ring.sign({
      coin: coin,
      value: value,
      address: address
    });

    const program = Program.fromScript({
      program: ring.script,
      address: ring.toAddress(),
      outpoint: new Outpoint(coin.hash, coin.index)
    });

    // The signature commits to the address and value
    const proof = SwapProof.fromOptions({
      version: 0,
      name: 'tester',
      program: program,
      signature: signature,
      address: address,
      value: value
    });

    // Using the name, its possible to look up the
    // outpoint that is locking the name and then
    // get the Coin object.

    const publicKey = proof.getPublicKey();

    // Bob's ring only gets Alice's public key
    const ring2 = SwapRing.fromPublicKey(publicKey);

    const valid = ring2.verify({
      coin: coin,
      value: value,
      address: address,
      signature: signature
    });

    assert.equal(valid, true);
  });
});
