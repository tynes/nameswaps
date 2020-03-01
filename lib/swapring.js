/**
 *
 */

'use strict';

const MTX = require('hsd/lib/primitives/mtx');
const Coin = require('hsd/lib/primitives/coin');
const Output = require('hsd/lib/primitives/output');
const rules = require('hsd/lib/covenants/rules');
const secp256k1 = require('bcrypto/lib/secp256k1');
const common = require('hsd/lib/script/common');

const SINGLEREVERSE = common.hashType.SINGLEREVERSE;
const ANYONECANPAY = common.hashType.ANYONECANPAY;
const SIGHASH_FLAG = ANYONECANPAY | SINGLEREVERSE;

/**
 * initialize
 *   send name to script
 *
 * create
 *   partially sign the transaction
 *
 * fill
 *   finish signing the transaction
 */

class SwapRing {
  constructor(options) {
    this.script = null;
    this.publicKey = null;
    this.privateKey = null;

    if (options)
      this.fromOptions(options);
  }

  fromOptions(options) {
    if (options.script != null)
      this.script = options.script;

    if (options.publicKey != null) {
      assert(Buffer.isBuffer(options.publicKey));
      assert(secp256k1.publicKeyVerify(options.publicKey));
      this.publicKey = options.publicKey;
    }

    if (options.privateKey != null) {
      assert(Buffer.isBuffer(options.privateKey));
      assert(secp256k1.privateKeyVerify(options.privateKey));
      this.privateKey = options.privateKey;
    }

    return this;
  }

  // TODO: create privatekey
  generate() {}

  fromPrivateKey(privkey) {
    assert(secp256k1.privateKeyVerify(privkey));
    this.privateKey = privkey;

    return this;
  }

  /**
   * Create initialization script.
   * Use with wallet.createTransfer
   *
   * The witness only needs to provide a signature
   */

  compile() {
    if (!this.publicKey) {
      assert(this.privateKey);
      this.publicKey = secp256k1.publicKeyCreate(this.privateKey, true);
    }

    assert(Buffer.isBuffer(this.publicKey));
    assert(secp256k1.publicKeyVerify(this.publicKey));

    this.script = new Script([
      Opcode.fromSymbol('type'),
      Opcode.fromInt(rules.types.UPDATE),
      Opcode.fromSymbol('equal'),
      Opcode.fromSymbol('if'),
      Opcode.fromSymbol('return'),
      Opcode.fromSymbol('endif'),

      Opcode.fromSymbol('type'),
      Opcode.fromInt(rules.types.REVOKE),
      Opcode.fromSymbol('equal'),
      Opcode.fromSymbol('if'),
      Opcode.fromSymbol('return'),
      Opcode.fromSymbol('endif'),

      Opcode.fromSymbol('type'),
      Opcode.fromInt(rules.types.RENEW),
      Opcode.fromSymbol('equal'),
      Opcode.fromSymbol('if'),
      Opcode.fromSymbol('return'),
      Opcode.fromSymbol('endif'),

      Opcode.fromSymbol('type'),
      Opcode.fromInt(rules.types.TRANSFER),
      Opcode.fromSymbol('equal'),
      Opcode.fromSymbol('if'),
      Opcode.fromPush(pubkey),
      Opcode.fromSymbol('checksigverify'),
      Opcode.fromSymbol('endif'),

      // fromSymbol('true')
      Opcode.fromInt(1)
    ]);

    this.script.compile();

    return this;
  }

  toAddress() {
    if (!this.script)
      this.compile();

    return Address.fromScript(this.script);
  }

  toScript() {
    if (!this.script)
      this.compile();
    return this.script;
  }

  sign(value, address) {
    const script = this.toScript();

    const Output = new Output({
      value: value,
      address: address
    });

    const mtx = this.toMTX(output)

    const signature = mtx.signature(0, script, value, this.privateKey, SIGHASH_FLAG);

    return signature;
  }

  // TODO: need coin that represents the name
  toMTX(coin, output) {
    const mtx = new MTX();
    // Add coin corresponding to the name here.
    mtx.addCoin(coin);

    // Counterparty fills in this coin.
    mtx.addCoin(new Coin());

    // This is not being signed, can be null
    mtx.addOutput(new Output({
      covenant: {
        type: rules.types.TRANSFER,
        items: []
      }
    }));

    // Change
    mtx.addOutput(new Output());

    // Output receiving in return for the name.
    mtx.addOutput(output);
  }

  static fromPublicKey(pubkey) {
    return new this().fromPublicKey(pubkey);
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  static fromPrivateKey(privkey) {
    return new this().fromPrivateKey(privkey);
  }
}

module.exports = SwapRing;
