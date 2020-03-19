/**
 *
 */

'use strict';

// Needs access to chain?
// wdb.getNameMap(nameHash) returns all wallets
//   watching a name

const SwapRing = require('./swapring');
const {states} = require('hsd/lib/covenants/namestate');
const rules = require('hsd/lib/covenants/rules');

// You do not want transactions to go away when
// Sometimes you need to wait some time before
// the transaction goes through. TRANSFER -> FINALIZE
// The initialize needs to submit a TRANSFER and then
// automatically submit a FINALIZE after some number
// of blocks.

// tx is the TRANSFER transaction
// pubkey is used in the nameswap template
// address is owned
// signature commits to address and value
class Listing {
  constructor(options) {
    this.name = null;
    this.tx = null;
    this.pubkey = null;
    this.address = null;
    this.signature = null;

    if (options)
      this.fromOptions(options);
  }

  validate() {
    if (!this.tx)
      return false;

    if (!this.pubkey)
      return false;

    if (!this.address)
      return false;

    if (!this.signature)
      return false;

    return true;
  }

  fromOptions(options) {
    if (options.name != null) {
      assert(typeof options.name === 'string');
      this.name = options.name;
    }

    if (options.tx != null) {
      this.tx = options.tx;
    }

    if (options.pubkey != null) {
      this.pubkey = options.pubkey;
    }

    if (options.address != null) {
      this.address = options.address;
    }

    if (options.signature != null) {
      this.signature = options.signature;
    }

    return this;
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }
}

class SwapsWallet {
  constructor(options) {
    this.options = new SwapsWalletOptions(options);

    this.wallet = options.wallet;
    this.chain = options.chain;
  }

  async verifyName(name) {
    if (!rules.verifyName(name))
      throw new Error('Invalid name.');

    const rawName = Buffer.from(name, 'ascii');
    const nameHash = rules.hashName(rawName);
    const height = this.wallet.wdb.height + 1;
    const network = this.wallet.wdb.network;

    if (rules.isReserved(nameHash, height, network))
      throw new Error('Name is reserved.');

    if (!rules.hasRollout(nameHash, height, network))
      throw new Error('Name not yet available.');

    let ns = await this.wallet.getNameState(nameHash);

    if (!ns)
      ns = await this.wallet.wdb.getNameStatus(nameHash);

    if (!ns.owner)
      throw new Error('No name owner.');

    ns.maybeExpire(height, network);

    const state = ns.state(height, network);

    if (state !== states.CLOSED)
      throw new Error('Name unavailable to transfer.');

    return ns;
  }


  /**
   * @returns {Array}
   * @returns {Listing}
   */

  async createListing(name, value) {
    assert(typeof name === 'string');

    // this throws
    const ns = await this.verifyName(name);
    assert(ns.owner);

    // need to go from ns.owner outpoint to utxo
    // how tf get that?

    const {hash, index} = ns.owner;

    // Check wallet for coin.
    let coin = await this.wallet.getCoin(hash, index);

    // Fall back to checking the chain.  This may not be necessary.  if (!coin) { assert(this.chain);
      coin = await this.chain.getCoin(hash, index);
    //}

    // TODO:
    // check that the ns.owner is an outpoint owned
    // by the current wallet
    // this.wallet.hasAddress(hsd.Address)

    // need to get a key from the wallet
    const keyring = await this.wallet.createReceive();
    const privkey = keyring.getPrivateKey();

    const swapring = Swapring.fromPrivateKey(privkey);

    // transfer is first transaction
    const address = swapring.toAddress();
    const tx = await this.wallet.createTransfer(name, address);
    // the finalize job will have to be created later

    // get change address to receive funds from counterparty
    const changeKeyring = await this.wallet.createChange();
    const change = changeKeyring.getAddress();

    const signature = swapring.sign(value, change);
    const pubkey = swapring.getPublicKey();

    const listing = new Listing.fromOptions({
      transaction: tx,
      publicKey: pubkey,
      address: address,
      signature: signature,
      name: name
    });

    assert(listing.validate());

    return listing;
  }

  fillListing() {

  }
}

class SwapsWalletOptions {
  constructor(options) {
    this.wallet = null;
    this.chain = null;

    if (options)
      this.fromOptions(options);
  }

  fromOptions(options) {
    if (options.wallet)
      this.wallet = options.wallet;

    if (options.chain)
      this.chain = options.chain;

    return this;
  }
}

module.exports = SwapsWallet;
