/**
 * addrwitness.js - AddrWitness for NameSwaps
 */

'use strict';

const bio = require('bufio');
const assert = require('bsert');
const Address = require('hsd/lib/primitives/address');
const Output = require('hsd/lib/primitives/output');
const blake2b = require('bcrypto/lib/blake2b');
const sha3 = require('bcrypto/lib/sha3');
const secp256k1 = require('bcrypto/lib/secp256k1');
const bech32 = require('bcrypto/lib/encoding/bech32');
const Network = require('hsd/lib/protocol/network');

/**
 * The type is defined by the shape of the data
 */

const types = {
  PUBKEY: 0,
  NAMESWAP: 1
};

const typesByVal = {
  [types.PUBKEY]: 'PUBKEY',
  [types.NAMESWAP]: 'NAMESWAP'
};

/**
 * An Address Witness satisfies the Address.
 *
 * Version 0:
 * Pay to Witness Pubkey Hash addresses are
 * satisfied by the preimage being a valid
 * pubkey.
 * Pay to Witness Script Hash addresses are
 * satisfied by being a valid script and
 * the preimage to the script hash.
 *
 * The AddrWitness is stored in the database
 * with the address as the key and the witness
 * as the value. An address is made up of a version
 * and data and the witness is made up of bytes.
 */

// TODO: implement getSize
class AddrWitness extends bio.Struct {
  constructor() {
    super();

    this.address = new Address();
    this.witness = null;
    this.outputs = [];
    this.network = Network.primary;
  }

  read(br, options) {
    this.witness = br.readVarBytes();

    const count = br.readU32();
    for (let i = 0; i < count; i++) {
      const output = Output.decode(br.readVarBytes());
      outputs.push(output);
    }

    if (options.network != null)
      this.network = options.network;

    if (options.address != null) {
      if (typeof options.address === 'string') {
        this.address = Address.fromString(options.address);
        if (!options.network) {
          const [hrp] = bech32.decode(options.address);
          this.network = Network.fromAddress(hrp);
        }

      } else
        this.address = options.address;
    }
  }

  write(bw) {
    bw.writeVarBytes(this.witness);

    bw.writeU32(this.outputs.length);
    for (let i = 0; i < this.outputs.length; i++)
      bw.writeVarBytes(outputs[i].encode());
  }

  /**
   *
   */

  getAddress() {
    return this.address;
  }

  /**
   * Create an AddrWitness from an Address
   * @param {hsd.Address|string} - addr
   * @param {Buffer|string} - witness
   * @param {hsd.Network?} - network
   * @returns {AddrWitness}
   */

  fromAddress(addr, witness, network) {
    assert(addr);

    if (network)
      this.network = network;

    if (typeof addr === 'string') {
      const [hrp] = bech32.decode(addr);
      this.network = Network.fromAddress(hrp);
      addr = Address.fromString(addr);
    }

    if (typeof witness === 'string')
      witness = Buffer.from(witness, 'hex');

    this.address = addr;
    this.witness = witness;
    return this;
  }

  /**
   * Validate an AddrWitness.
   * Optionally pass a network
   * for extra validation.
   * @param {Network?}
   * @returns {Boolean}
   */

  isValid(network) {
    if (this.address.isNull())
      return false;

    if (!this.address.isValid())
      return false;

    if (this.address.version === 0) {
      // Handle P2WPKH
      if (this.address.hash.length === 20) {
        // Public key must be 33 bytes
        if (this.witness.length !== 33)
          return false;

        if (!secp256k1.publicKeyVerify(this.witness))
          return false;

        const hash = blake2b.digest(this.witness, 20);
        if (!hash.equals(this.address.hash))
          return false;
      }

      // Handle P2WPKH
      if (this.address.hash.length === 32) {
        const hash = sha3.digest(this.witness);
        if (!hash.equals(this.address.hash))
          return false;
      }

      return true;
    }

    // Explicitly fail on unknown address versions.
    return false;
  }

  type() {
    if (secp256k1.publicKeyVerify(this.witness))
      return types.PUBKEY;

    // TODO(mark): if the witness matches the nameswaps
    // template return types.NAMESWAP.
  }

  fromJSON(json) {
    assert(typeof json.address === 'string');
    if (json.witness)
      assert(typeof json.witness === 'string');

    const [hrp] = bech32.decode(json.address);
    this.network = Network.fromAddress(hrp);
    this.address = Address.fromString(json.address);
    this.witness = Buffer.from(json.witness, 'hex');

    return this;
  }

  toJSON() {
    return {
      address: this.address.toString(this.network.type),
      witness: this.witness.toString('hex'),
      type: typesByVal[this.type()]
    };
  }

  static fromAddress(addr, witness, network) {
    return new this().fromAddress(addr, witness, network);
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }
}

AddrWitness.types = types;
AddrWitness.typesByVal = typesByVal;
module.exports = AddrWitness;
