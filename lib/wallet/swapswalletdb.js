/**
 *
 */

'use strict';

const assert = require('bsert');
const EventEmitter = require('events');
const path = require('path');
const bdb = require('bdb');
const Logger = require('blgr');
const Network = require('hsd/lib/protocol/network');
const Path = require('hsd/lib/wallet/path');
const {Lock} = require('bmutex');
const layouts = require('./layout');
const layout = layouts.swdb;

class SwapsWalletDB extends EventEmitter {
  constructor(options) {
    super();

    this.options = new SwapsWalletOptions(options);
    this.wdb = options.wdb;
    this.logger = this.options.logger.context('swaps-wallet');

    this.db = bdb.create(this.options);
    this.writeLock = new Lock();
    // TODO: probably need readLock
  }

  async open() {
    await this.db.open();

    await this.watch();
  }

  async close() {
    await this.db.close();
  }

  async watch() {
    const piter = this.db.iterator({
      gte: layout.p.min(),
      lte: layout.p.max()
    });

    let hashes = 0;

    await piter.each((key) => {
      const [data] = layout.decode(key);
      this.wdb.filter.add(data);
      hashes += 1;
    });

    this.logger.info('Added %s hashes to the WalletDB filter.', hashes);

    // TODO: Add outpoints to the map as well?
  }

  saveKey(b, wid, ring) {
    return this.savePath(b, wid, ring.toPath());
  }

  /**
   * This must be its own index because it would
   * overwrite the walletdb's index.
   */

  async savePath(b, wid, path) {
    await this.addPathMap(b, path.hash, wid);
    b.put(layout.P.encode(wid, path.hash), path.encode());
    b.put(layout.r.encode(wid, path.account, path.hash), null);
  }

  async getPath(wid, hash) {
    const path = await this.readPath(wid, hash);

    if (!path)
      return null;

    path.name = await this.wdb.getAccountName(wid, path.account);
    assert(path.name);

    return path;
  }

  async readPath(wid, hash) {
    const data = await this.db.get(layout.P.encode(wid, hash));

    if (!data)
      return null;

    const path = Path.decode(data);
    path.hash = hash;

    return path;
  }

  async addPathMap(b, hash, wid) {
    await this.addHash(hash);
    return this.wdb.addMap(b, layout.p.encode(hash), wid);
  }

  async addHash(hash) {
    this.wdb.filter.add(hash);
    return this.wdb.addFilter(hash);
  }

  /**
   * @param {WalletKey} key
   */

  async putKeyData(acct, key) {
    const unlock = await this.writeLock.lock();
    try {
      return await this._putKeyData(acct, key);
    } catch (e) {
      this.emit('error', e);
    } finally {
      unlock();
    }
  }

  // TODO: this needs to go in swapstxwalletdb
  // TODO: this needs to accept a batch?
  // Where does the bucket get created?
  async _putKeyData(acct, key) {
    assert(typeof acct === 'number');
    const prefix = layout.prefix.encode(acct);
    const bucket = this.db.bucket(prefix);

  }
}

class SwapsWalletOptions {
  constructor(options) {

    this.logger = Logger.global;
    this.network = Network.primary;
    this.module = 'swapswalletdb';
    this.prefix = null;
    this.location = null;
    this.memory = true;
    this.maxFiles = 64;
    this.cacheSize = 16 << 20;
    this.compression = true;

    if (options)
      this.fromOptions(options);
  }

  fromOptions(options) {
    assert(options.wdb, 'Must pass wallet db');
    this.wdb = options.wdb;

    if (options.logger != null)
      this.logger = options.logger;

    if (options.prefix != null) {
      assert(typeof options.prefix === 'string');

      this.prefix = options.prefix;
      this.prefix = path.join(this.prefix, this.module);
      this.location = this.prefix;
    }

    if (options.location != null) {
      assert(typeof options.location === 'string');
      this.location = options.location;
    }

    if (options.memory != null) {
      assert(typeof options.memory === 'boolean');
      this.memory = options.memory;
    }

    if (options.maxFiles != null) {
      assert((options.maxFiles >>> 0) === options.maxFiles);
      this.maxFiles = options.maxFiles;
    }

    if (options.cacheSize != null) {
      assert(Number.isSafeInteger(options.cacheSize) && options.cacheSize >= 0);
      this.cacheSize = options.cacheSize;
    }

    if (options.compression != null) {
      assert(typeof options.compression === 'boolean');
      this.compression = options.compression;
    }

    return this;
  }

}

module.exports = SwapsWalletDB;
