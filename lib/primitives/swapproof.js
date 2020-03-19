/**
 *
 */

'use strict';

const bio = require('bufio');
const assert = require('bsert');
const Address = require('hsd/lib/primitives/address');
const Outpoint = require('hsd/lib/primitives/outpoint');
const Network = require('hsd/lib/protocol/network');
const blake2b = require('bcrypto/lib/blake2b');
const InvItem = require('../net/invitem');
const Program = require('./program');
const ZERO_64 = Buffer.alloc(64);
const {invTypes} = InvItem;

// Need to use Outpoint instead of Address
// Index based on outpoint
// Still allow getting by address via REST API
// by using chain.getCoinsByAddress and then
// getting each outpoint from each coin and
// then checking for each in the nameswaps index
// SwapProofs indexed by name

class SwapProof extends bio.Struct {
  constructor(options) {
    super();

    this.version = 0;
    this.name = '';
    this.program = new Program();
    this.signature = ZERO_64;
    this.address = new Address();
    this.value = 0;

    // Not serialized
    this._hash = null;
    this.network = Network.primary;

    if (options)
      this.fromOptions(options);
  }

  fromOptions(options) {
    if (typeof options.version === 'number') {
      assert((options.version >>> 0) === options.version);
      this.version = options.version;
    }

    if (typeof options.name === 'string') {
      this.name = options.name;
    }

    if (options.program) {
      assert(options.program instanceof Program);
      this.program = options.program;
    }

    if (options.signature) {
      assert(Buffer.isBuffer(options.signature));
      assert(options.signature.length === 64);
      this.signature = options.signature;
    }

    if (options.address) {
      assert(options.address instanceof Address);
      this.address = options.address;
    }

    if (typeof options.value === 'number') {
      this.value = options.value;
    }

    if (options.network) {
      if (typeof options.network === 'string')
        this.network = Network.get(options.network);
      else
        this.network = options.network;
    }

    return this;
  }

  fromJSON(json) {
    assert(typeof json.version === 'number');
    assert((json.version >>> 0) === json.version);
    assert(typeof json.name === 'string');
    assert(json.program);
    assert(typeof json.signature === 'string');
    assert(json.address);
    assert(typeof json.value === 'number');

    this.version = json.version;
    this.name = json.name;
    this.program = Program.fromJSON(json.program);
    this.signature = Buffer.from(json.signature, 'hex');
    this.address = Address.fromString(json.address);
    this.value = json.value;

    if (json.network)
      this.network = Network.get(json.network);

    return this;
  }

  getSize() {
    let size = 0;
    size += 1;
    size += bio.encoding.sizeVarString(this.name);
    size += bio.encoding.sizeVarBytes(this.program.encode());
    size += this.signature.length;
    size += bio.encoding.sizeVarBytes(this.address.encode());
    size += 8;
    return size;
  }

  read(br, network) {
    this.version = br.readU8();
    this.name = br.readVarString();
    this.program = Program.decode(br.readVarBytes());
    this.signature = br.readBytes(64);
    this.address = Address.decode(br.readVarBytes());
    this.value = br.readU64();

    if (network) {
      if (typeof network === 'string')
        this.network = Network.get(network);
      else
        this.network = network;
    }

    return this;
  }

  // TODO: could refactor out the name, but need
  // that for p2p serialization
  write(bw) {
    bw.writeU8(this.version);
    bw.writeVarString(this.name);
    bw.writeVarBytes(this.program.encode());
    bw.writeBytes(this.signature);
    bw.writeVarBytes(this.address.encode());
    bw.writeU64(this.value);
    return this;
  }

  toJSON() {
    return {
      version: this.version,
      name: this.name,
      program: this.program.toJSON(),
      signature: this.signature.toString('hex'),
      address: this.address.toString(this.network.type),
      value: this.value
    }
  }

  toInv() {
    return new InvItem(invTypes.SWAPPROOF, this.hash());
  }

  hash() {
    if (!this._hash) {
      const addr = this.address.encode();

      const bw = new bio.BufferWriter(8);
      const value = bw.writeU64(this.value).encode();

      this._hash = blake2b.multi(this.signature, addr, value);
    }

    return this._hash;
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }
}

module.exports = SwapProof;
