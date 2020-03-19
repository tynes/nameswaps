/**
 *
 */

'use strict';

const bio = require('bufio');
const assert = require('assert');
const Outpoint = require('hsd/lib/primitives/outpoint');
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

    // Serialized only for p2p
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
    this.outpoint = new Outpoint(extra.hash, extra.index);
    return this;
  }

  write(bw, p2p) {
    bw.writeU8(this.type);
    bw.writeVarBytes(this.data);
    bw.writeBytes(this.outpoint.encode());

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
}

Program.types = types;
Program.typesByVal = typesByVal;

module.exports = Program;
