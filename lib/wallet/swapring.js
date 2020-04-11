/**
 *
 */

'use strict';

const assert = require('bsert');
const MTX = require('hsd/lib/primitives/mtx');
const Coin = require('hsd/lib/primitives/coin');
const Output = require('hsd/lib/primitives/output');
const Script = require('hsd/lib/script/script');
const Address = require('hsd/lib/primitives/address');
const Witness = require('hsd/lib/script/witness');
const rules = require('hsd/lib/covenants/rules');
const secp256k1 = require('bcrypto/lib/secp256k1');
const common = require('hsd/lib/script/common');
const Scripts = require('./scripts');

const SINGLEREVERSE = common.hashType.SINGLEREVERSE;
const ANYONECANPAY = common.hashType.ANYONECANPAY;
const SIGHASH_FLAG = ANYONECANPAY | SINGLEREVERSE;

const ZERO_KEY = Buffer.alloc(32);
const ZERO_PUBKEY = Buffer.alloc(33);

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
    this.type = 0;
    this.script = new Script();
    this.privateKey = ZERO_KEY;
    this.publicKey = ZERO_PUBKEY;

    if (options)
      this.fromOptions(options);
  }

  fromOptions(options) {
    if (options.script != null)
      this.script = options.script;

    if (typeof options.type === 'number')
      this.type = options.type;

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

  fromPublicKey(pubkey) {
    assert(secp256k1.publicKeyVerify(pubkey));
    this.publicKey = pubkey;
    this.compile();

    return this;
  }

  generate(type) {
    this.privateKey = secp256k1.privateKeyGenerate();
    this.publicKey = secp256k1.publicKeyCreate(this.privateKey);
    this.compile(type);

    return this;
  }

  fromPrivateKey(privkey) {
    assert(secp256k1.privateKeyVerify(privkey));
    this.privateKey = privkey;
    this.publicKey = secp256k1.publicKeyCreate(this.privateKey);
    this.compile();

    return this;
  }

  /**
   * Create initialization script.
   * Use with wallet.createTransfer
   *
   * The witness only needs to provide a signature
   */

  compile(type) {
    if (!this.publicKey) {
      assert(this.privateKey);
      this.publicKey = secp256k1.publicKeyCreate(this.privateKey, true);
    }

    if (typeof type === 'number')
      this.type = type;

    assert(Buffer.isBuffer(this.publicKey));
    assert(secp256k1.publicKeyVerify(this.publicKey));

    const template = Scripts.fromType(this.type, this.publicKey);
    this.script = template.getScript();

    return this;
  }

  toAddress() {
    return Address.fromScript(this.script);
  }

  sign(data) {
    switch (this.type) {
      case Scripts.types.NAIVE: {
        const {coin, value, address} = data;
        assert(coin && value && address);

        const script = this.script;
        const output = new Output({value, address});
        const mtx = this.toMTX({coin, output});
        const flag = Scripts.flagsByType[this.type];
        assert(flag, 'Invalid type, flag not found');

        return mtx.signature(0, script, value, this.privateKey, flag);
      }
      default:
        return null;
    }
  }

  /**
   *
   */

  toMTX(data) {
    switch (this.type) {
      case Scripts.types.NAIVE: {
        const {coin, output} = data;
        assert(coin && output);

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

        return mtx;
      }
      default:
        return null;
    }
  }

  toWitness(data) {
    switch (this.type) {
      case Scripts.types.NAIVE: {
        const {signature} = data;
        assert(signature);

        const script = this.script;

        const witness = new Witness([
          signature,
          script.encode()
        ]);

        witness.compile();
        return witness;
      }
      default:
        return null;
    }
  }

  verify(data) {
    let type = data.type;
    if (type == null)
      type = this.type;

    // Each case must return a boolean
    switch (type) {
      case Scripts.types.NAIVE: {
        const {coin, value, address} = data;
        let {signature} = data;

        const flag = Scripts.flagsByType[this.type];
        assert(flag, 'Invalid type, flag not found');

        if (!signature)
          signature = this.sign({coin, value, address});

        const output = new Output({value, address});
        const mtx = this.toMTX({coin, output});

        mtx.inputs[0].witness = this.toWitness({signature, publicKey: this.publicKey});

        try {
          mtx.checkInput(0, coin, flag);
          return true;
        } catch (e) {
          return false;
        }
      }
      default:
        return false;
    }
  }

  static fromPublicKey(publicKey) {
    return new this().fromPublicKey(publicKey);
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  static fromPrivateKey(privateKey) {
    return new this().fromPrivateKey(privateKey);
  }

  static generate() {
    return new this().generate();
  }
}

module.exports = SwapRing;
