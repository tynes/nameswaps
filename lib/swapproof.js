/**
 *
 */

'use strict';

const bio = require('bufio');
const assert = require('bsert');
const Address = require('hsd/lib/primitives/address');
const blake2b = require('bcrypto/lib/blake2b');
const InvItem = require('./invitem');
const Program = require('./program');
const ZERO_64 = Buffer.alloc(64);
const {invTypes} = InvItem;

// Need to use Outpoint instead of Address
// Index based on outpoint
// Still allow getting by address via REST API
// by using chain.getCoinsByAddress and then
// getting each outpoint from each coin and
// then checking for each in the nameswaps index

class SwapProof extends bio.Struct {
  constructor(options) {
    super();

    this.version = 0;
    this.program = new Program();
    this.signature = ZERO_64;
    this.address = new Address();
    this.value = 0;

    // Not serialized
    this._hash = null;

    if (options)
      this.fromOptions(options);
  }

  fromOptions(options) {
    // TODO:
    // assert on each of the types being passed in

  }

  getSize() {
    const size = this.address.getSize();

    return 64
     + bufio.encoding.sizeVarInt(size)
     + size
     + 8;
  }

  read(br) {
    this.signature = br.readBytes(64);
    this.address = br.readVarBytes();
    this.value = br.readU64();
  }

  write(bw) {
    bw.writeBytes(this.signature);
    bw.writeVarBytes(this.address.encode());
    bw.writeU64(this.value);
  }

  toInv() {
    return new InvItem(invTypes.SWAPPROOF, this.hash());
  }

  hash() {
    if (!this._hash) {
      const addr = this.address.encode();
      const bw = new bufio.BufferWriter(8);
      const value = bw.writeU64(this.value).encode();
      this._hash = blake2b.multi(this.signature, addr, value);
    }

    return this._hash;
  }
}

module.exports = SwapProof;
