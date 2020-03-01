/**
 * lib/swapsdb.js - SwapsDB for NameSwaps
 */

'use strict';

const assert = require('bsert');
const EventEmitter = require('events');
const bdb = require('bdb');
const Network = require('hsd/lib/protocol/network');
const AddrWitness = require('./addrwitness');
const layout = require('./layout');
const Logger = require('blgr')

class SwapsDB extends EventEmitter {
  constructor(options) {
    super();

    this.options = new SwapsDBOptions(options);
    this.network = this.options.network;
    this.logger = this.options.logger.context('swapsdb');

    this.db = bdb.create(this.options);
  }

  async open() {
    this.logger.info('Opening SwapsDB...');

    await this.db.open();

    // TODO: how to handle version?
    //await this.db.verify(layout.V.encode(), 'chain', 0);
  }

  async close() {
    await this.db.close();
  }

  /**
   * Get the blockhash corresponding to the tip
   * known by the NameSwaps plugin.
   * @returns {Hash}
   */

  async getTip() {
    const tip = await this.db.get(layout.R.encode());

    if (!tip)
      return null;

    return tip;
  }

  /**
   * Put the blockhash corresponding to the latest
   * tip of the blockchain.
   * @param {Hash}
   * @return {Hash}
   */

  async putTip(hash) {
    const key = layout.R.encode();
    try {
      await this.db.put(key, hash);
    } catch (e) {
      this.emit('error', e);
      return null;
    }

    return hash;
  }

  /**
   * @param {hsd.Address}
   */

  async getAddrWitness(addr) {
    const {version, hash} = addr;
    const key = layout.a.encode(version, hash);

    const raw = await this.db.get(key);

    if (!raw)
      return null;

    return AddrWitness.decode(raw, {
      address: addr,
      network: this.network
    });
  }

  /**
   * @param {AddrWitness} - addrwitness
   */

  async putAddrWitness(addrwitness) {
    const addr = addrwitness.getAddress();

    const {version, hash} = addr;
    const key = layout.a.encode(version, hash);

    try {
      await this.db.put(key, addrwitness.encode());
    } catch (e) {
      this.emit('error', e);
      return null;
    }

    return addr;
  }

  /**
   * @param {hsd.Address} - addr
   */

  async hasAddrWitness(addr) {
    const {version, hash} = addr;
    const key = layout.a.encode(version, hash);

    return this.db.has(key);
  }

  /**
   * @param {hsd.Address} - addr
   */

  async deleteAddrWitness(addr) {
    const {version, hash} = addr;
    const key = layout.a.encode(version, hash);

    try {
      await this.db.del(key);
    } catch (e) {
      this.emit('error', e);
      return null;
    }

    return addr;
  }

  /**
   *
   */

  async getAddrWitnesses() {
    return null;
  }

  /**
   *
   */

  async getJobsByHeight(height) {
    assert((height >>> 0) === height);

    const key = layout.j.encode(height);
    const raw = await this.db.get(key);

    if (!raw)
      return null;

    return JobList.decode(raw, height);
  }

  /**
   *
   */

  // TODO: break this up by height
  // TODO: flatten this array
  async getJobs() {
    return this.db.range({
      gte: layout.j.min(),
      lte: layout.j.max(),
      parse: (key, value) => {
        const height = layout.j.decode(key);
        return JobList.decode(value, height);
      }
    });
  }

  /**
   *
   */

  putJobByName(name, job) {
    if (typeof name === 'string')
      name = Buffer.from(name, 'ascii');

    const key = layout.n.encode(name);

    await db.put(key, job.encode());

    return job;
  }

  /**
   *
   */

  putJobByHeight(height, job) {
    assert(typeof height === 'number');

    const key = layout.j.encode(height);
    await db.put(key, job.encode());

    return job;
  }

  /**
   *
   */

  async wipe() {
    this.logger.warning('Wiping SwapsDB...');

    const iter = this.db.iterator();
    const b = this.db.batch();

    let total = 0;

    await iter.each((key) => {
      switch (key[0]) {
        case 0x56: // V
        case 0x52: // R
        case 0x61: // a
          b.del(key);
          total += 1;
          break;
      }
    });

    this.logger.warning('Wiped %d txdb records.', total);

    return b.write();
  }
}

class SwapsDBOptions {
  constructor(options) {
    this.logger = Logger.global;

    this.network = Network.primary;
    this.prefix = null;
    this.location = null;
    this.memory = true;
    this.maxFiles = 64;
    this.cacheSize = 16 << 20;
    this.compression = true;

    if (options)
      this.fromOptions(options)
  }

  fromOptions(options) {
    if (options.network != null) {
      this.network = options.network;
    }

    if (options.prefix != null) {
      assert(typeof options.prefix === 'string');
      this.prefix = options.prefix;
      this.prefix = path.join(this.prefix, 'index');
      this.location = path.join(this.prefix, this.module);
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

module.exports = SwapsDB;
