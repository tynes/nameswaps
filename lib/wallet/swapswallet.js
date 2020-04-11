/**
 *
 */

'use strict';

// Needs access to chain?
// wdb.getNameMap(nameHash) returns all wallets
//   watching a name

const EventEmitter = require('events');
const SwapRing = require('./swapring');
const {states} = require('hsd/lib/covenants/namestate');
const rules = require('hsd/lib/covenants/rules');
const Listing = require('./listing');
const SwapsWalletDB = require('./swapswalletdb');

// You do not want transactions to go away when
// Sometimes you need to wait some time before
// the transaction goes through. TRANSFER -> FINALIZE
// The initialize needs to submit a TRANSFER and then
// automatically submit a FINALIZE after some number
// of blocks.


class SwapsWallet extends EventEmitter {
  constructor(options) {
    super();

    this.options = new SwapsWalletOptions(options);

    this.wallet = options.wallet;
    this.wdb = options.wdb;
    this.network = this.options;
    this.swdb = options.swdb;

    //this.init();
  }

  init() {
    this.swdb.on('error', this.emit('error'));
  }

  /**
   * hsd.Address
   * It is going to be a pw2sh. Want to return
   * a program along with the templated public key
    // look up in custom index

    // scripthash -> path
    // scripthash -> program
   */

  getKey(address) {
    const hash = Address.getHash(address);
    const path = this.getPath(hash);

    if (!path)
      return null;

    const account = await this.wallet.getAccount(path.account);

    if (!account)
      return null;

    // TODO: fix watch only wallet bug

    const derived = account.derivePath(path, this.wallet.master);
    // TODO: probably need to template ring correctly here...

    return derived;
  }

  getPath() {
    const hash = Address.getHash(address);
    return this.swdb.getPath(this.wallet.wid, hash);
  }

  async createReceive(acct = 0) {
    const key = await this.wallet.createReceive(acct);
    const ring = SwapRing.fromPublicKey(key.publicKey);
    const script = ring.script;
    key.script = ring.script;

    const b = this.swdb.db.batch();
    await this.swdb.saveKey(b, this.wallet.wid, key);
    await b.write();


    // This should index
    //   scripthash -> path
    //   scripthash -> program
    //await this.stxdb.putKeyData(ring);

    return key;
  }

  async createChange(acct = 0) {

  }

  // TODO: this might be out of date.
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

  // TODO: this is old and out of date, likely should
  // replace it with something else.
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
      //coin = await this.chain.getCoin(hash, index);
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
    this.wdb = null;
    this.swdb = null;

    if (options)
      this.fromOptions(options);
  }

  fromOptions(options) {
    if (options.wallet)
      this.wallet = options.wallet;

    if (options.wdb)
      this.wdb = options.wdb;

    if (options.swdb)
      this.swdb = options.swdb;

    return this;
  }
}

module.exports = SwapsWallet;
