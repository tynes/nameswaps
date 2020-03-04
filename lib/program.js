/**
 *
 */

'use strict';

const bio = require('bufio');
const Address = require('hsd/lib/primitives/address');
const InvItem = require('./invitem');
const {invTypes} = InvItem;

const EMPTY = Buffer.alloc(0);

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

    // Not serialized but required for p2p
    this.address = new Address();
  }

  getSize() {
    const size = bufio.encoding.sizeVarInt(this.data);
    switch (this.type) {
      case types.NONE:
        return 4 + size + 1;
      case types.PUBKEY:
      case types.SCRIPT:
        return 4 + size + this.data.length;
      default:
        throw new Error('Unknown Program type.');
    }
  }

  read(br) {
    this.type = br.readU8();
    this.data = br.readVarBytes();
  }

  write(bw) {
    bw.writeU8(this.type);
    bw.writeVarBytes(this.data);
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
    // assert that the address is not null
    return this.address.encode();
  }

  toInv() {
    return new InvItem(invTypes.SWAPPROOF, this.toKey());
  }
}

Program.types = types;
Program.typesByVal = typesByVal;

module.exports = Program;
