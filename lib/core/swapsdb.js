/**
 * lib/swapsdb.js - SwapsDB for NameSwaps
 */

'use strict';

const assert = require('bsert');
const EventEmitter = require('events');
const bdb = require('bdb');
const fs = require('bfile');
const Network = require('hsd/lib/protocol/network');
const Outpoint = require('hsd/lib/primitives/outpoint');
const path = require('path');
const SwapProof = require('../primitives/swapproof');
const Program = require('../primitives/program');
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

    await this.ensure();
    await this.db.open();

    // TODO: how to handle version?
    //await this.db.verify(layout.V.encode(), 'chain', 0);
  }

  async ensure() {
    if (fs.unsupported)
      return;

    if (this.options.memory)
      return;

    await fs.mkdirp(this.options.prefix);
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

  async getSwapProof(name) {
    const key = layout.s.encode(name);

    const raw = await this.db.get(key);

    if (!raw)
      return null;

    return SwapProof.decode(raw, this.network);
  }

  // TODO: could refactor out the name
  // for the db serialization of the
  // swap proof, although would need it
  // for p2p serialization.
  async getSwapProofs() {
    let i = 0;
    return this.db.values({
      gte: layout.s.min(),
      lte: layout.s.max(),
      parse: (value) => {
        return SwapProof.decode(value, this.network);
      }
    });
  }

  async putSwapProof(name, proof) {
    const key = layout.s.encode(name);
    const raw = proof.encode();

    try {
      await this.db.put(key, raw);
    } catch (e) {
      this.emit('error', e);
      return null;
    }

    return proof;
  }

  async hasSwapProof(name) {
    const key = layout.s.encode(name);
    return this.db.has(key);
  }

  // TODO: need to add functionality to
  // prune the db of proofs that have
  // already been claimed, or add that
  // into the db serialization
  async deleteSwapProof(name) {
    const key = layout.s.encode(name);

    try {
      await this.db.del(key);
    } catch (e) {
      this.emit('error', e);
      return null;
    }

    return name;
  }

  async getProgram(hash, index) {
    const key = layout.p.encode(hash, index);

    const raw = await this.db.get(key);

    if (!raw)
      return null;

    const program = Program.decode(raw);
    program.outpoint = new Outpoint(hash, index);

    return program;
  }

  async getPrograms() {
    return this.db.values({
      gte: layout.p.min(),
      lte: layout.p.max(),
      parse: (value) => {
        return Program.decode(value);
      }
    });
  }

  async getProgramOutpointsByBlock(hash) {
    return this.db.keys({
      gte: layout.P.min(hash),
      lte: layout.P.max(hash),
      parse: (key) => {
        const [, txid, index] = layout.P.decode(key);
        return new Outpoint(txid, index);
      }
    });
  }

  async putProgram(hash, index, program) {
    const key = layout.p.encode(hash, index);

    try {
      await this.db.put(key, program.encode());
    } catch (e) {
      this.emit('error', e);
      return null;
    }

    return program;
  }

  async hasProgram(hash, index) {
    const key = layout.p.encode(hash, index);
    return this.db.has(key);
  }

  async deleteProgram(hash, index) {
    const key = layout.p.encode(hash, index);

    try {
      await this.db.del(key);
    } catch (e) {
      this.emit('error', e);
      return null;
    }

    // TODO: i hate polymorphic functions
    return true;
  }

  // TODO: think deeply about the job stuff,
  // potentially explore just using a mempool
  // for future txs instead that can just
  // be broadcasted to the network by anybody

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

  async putJobByName(name, job) {
    if (typeof name === 'string')
      name = Buffer.from(name, 'ascii');

    const key = layout.n.encode(name);

    await db.put(key, job.encode());

    return job;
  }

  /**
   *
   */

  async putJobByHeight(height, job) {
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
    this.module = 'swapsdb';
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
      this.prefix = path.join(this.prefix, this.module);
      // TODO: figure out if additional data is required
      // to be stored, if so, set this.location to
      // path.join(this.prefix, 'index')
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

module.exports = SwapsDB;
