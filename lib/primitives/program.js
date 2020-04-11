/**
 *
 */

'use strict';

const bio = require('bufio');
const assert = require('assert');
const Outpoint = require('hsd/lib/primitives/outpoint');
const Script = require('hsd/lib/script/script');
const Address = require('hsd/lib/primitives/address');
const InvItem = require('../net/invitem');
const {invTypes} = InvItem;

const EMPTY = Buffer.alloc(1);

const types = {
  NONE: 0,
  PUBKEY: 1,
  SCRIPT: 2
};

const typesByVal = {
  [types.NONE]: 'NONE',
  [types.PUBKEY]: 'PUBKEY',
  [types.SCRIPT]: 'SCRIPT'
};

// Need to use outpoint instead of address
// Will only work with utxos that currently exist
// on receive of a ProgramPacket, look up in the chain,
// if it doesn't exist look up in the mempool,
// if it doesn't exist send NotFound and up the banscore
// on that peer

class Program extends bio.Struct {
  constructor() {
    super();

    this.type = types.NONE;
    this.data = EMPTY;
    this.outpoint = new Outpoint();
  }

  fromOptions(options) {
    if (typeof options.type === 'number') {
      assert((options.type >>> 0) === options.type);
      this.type = options.type;
    }

    if (options.data) {
      assert(Buffer.isBuffer(options.data));
      this.data = options.data;
    }

    if (options.outpoint) {
      assert(options.outpoint instanceof Outpoint);
      this.outpoint = options.outpoint;
    }

    return this;
  }

  fromJSON(json) {
    assert(typeof json.type === 'string');
    assert(json.type in types);
    assert(typeof json.data === 'string');

    this.type = types[json.type];
    this.data = json.data;

    if (json.outpoint)
      this.outpoint = Outpoint.fromJSON(json.outpoint);

    return this;
  }

  getSize() {
    let size = 0;

    size += 1;
    size += bio.encoding.sizeVarBytes(this.data);
    size += this.outpoint.getSize();

    return size;
  }

  read(br, extra) {
    this.type = br.readU8();
    this.data = br.readVarBytes();

    // TODO: no check for extra here causes issues...
    // Would rather them not being silent for now.
    this.outpoint = new Outpoint(extra.hash, extra.index);
    return this;
  }

  write(bw) {
    bw.writeU8(this.type);
    bw.writeVarBytes(this.data);
    bw.writeBytes(this.outpoint.encode());

    return this;
  }

  isNull() {
    return this.data.equals(EMPTY) && this.type === types.NONE;
  }

  // This API is slightly off because the program
  // here is an instance of a Script.
  fromScript(data) {
    const {address, program, outpoint} = data;
    assert(address && program && outpoint);
    const {hash, index} = outpoint;

    let addr;
    if (address.isPubkeyhash()) {
      addr = Address.fromPubkey(progam);
      this.type = types.PUBKEY;
    } else if (address.isScripthash()) {
      addr = Address.fromScript(program);
      this.type = types.SCRIPT;
    }

    assert(addr.equals(address));

    this.data = program.encode();
    this.outpoint = new Outpoint(hash, index);

    return this;
  }

  fromAddress(address, program) {
    // assert valid address
    // assert the program is
    //   - a pubkey
    //   - a pubkey hash
    //   - a script preimage
    //   - a script hash
    // assign variables correctly
  }

  toKey() {
    return this.outpoint.encode();
  }

  hash() {
    throw new Error('Program.hash not implemented');
  }

  toInv() {
    return new InvItem(invTypes.PROGRAM, this.toKey());
  }

  toJSON() {
    return {
      type: typesByVal[this.type],
      data: this.data.toString('hex'),
      outpoint: this.outpoint.toJSON()
    }
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }

  static fromScript(script) {
    return new this().fromScript(script);
  }
}

Program.types = types;
Program.typesByVal = typesByVal;

module.exports = Program;
