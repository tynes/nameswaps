/*!
 * swaps.js - NameSwaps for hsd
 * Copyright (c) 2020, Mark Tyneway (Apache-2.0 License).
 * https://github.com/tynes/hsd-nameswaps
 *
 * This software is based on bcoin
 * https://github.com/bcoin-org/bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * Copyright (c) 2017-2019, bcoin developers (MIT License).
 */

'use strict';

const AsyncEmitter = require('bevent');
const assert = require('assert');
const {Lock} = require('bmutex');
const Logger = require('blgr');
const SwapsDB = require('./swapsdb');
const AddrWitness = require('./addrwitness');
const Address = require('hsd/lib/primitives/address');
const {BufferSet} = require('buffer-map');
const {Job} = require('./jobs');
const layout = require('./layout');

/**
 * Set up listeners on the chain for 'connect' and 'disconnect'
 *   update tip index on each connected/disconnected block
 * Keep a tip index, just a block hash
 * On start get the tip, check to make sure it is in the main chain
 *   if not, find ancenstor and then scan from that height
 *   if yes, then scan forwards from that block to the tip
 *
 * POST /nameswaps/address
 *  - validate the address
 *  - index
 *  - gossip
 *
 * On 'connect'
 *  - For each consumed UTXO
 *      if there still exists another UTXO with same addr, index witness
 *      if no UTXOs with addr exist and the db has the addr, delete from db
 *
 * On 'disconnect'
 *  - For each no longer consumed UTXO
 *      if there is not another UTXO with same addr, remove from db
 */

class NameSwaps extends AsyncEmitter {
  constructor(options) {
    super();

    this.options = new NameSwapsOptions(options);
    this.logger = this.options.logger.context('nameswaps');
    this.chain = this.options.chain;
    //this.pool = this.options.pool;
    this.network = this.options.network;

    this.writeLock = new Lock();

    this.sdb = new SwapsDB({
      chain: this.options.chain,
      network: this.network,
      logger: this.logger,
      memory: this.options.memory,
      prefix: this.options.prefix,
    });
  }

  /**
   *
   */

  async open() {
    this.listen();
    await this.sdb.open();
  }

  /**
   * Set up event listeners.
   */

  listen() {
    this.sdb.on('error', (error) => this.emit('error', error));
    this.on('error', error => this.logger.error('Error: %o', error));

    this.chain.on('connect', async (entry, block, view) => {
      // For transaction, iterate over the outputs
      // and look for one that we are interested in.
      for (const tx of block.txs) {
        for (const output of tx.outputs) {
          // can we index the address instead so that
          // it also works with pay to pubkey hash?

          // if the output type is TRANSFER
          if (output.covenant.isTransfer()) {
            const nameHash = output.covenant.getHash(0)
            const ns = await view.getNameState(this.db, nameHash);
            const name = ns.name.toString('ascii');

            if (this.hasJobByName(name)) {
              const joblist = await this.getJobListByName(name);
              for (const job of joblist) {
                const result = await job.execute();

                if (!result) {
                  this.logger.error('Very very bad.');
                } else {
                  // remove job from database
                }
              }
            }
          }
        }
      }

      this.emit('block connect');
    });

    this.chain.on('disconnect', () => {
      this.emit('block disconnect');
    });

    /*

    this.pool.on('')
    */
  }

  /**
   * Handle graceful shutdown.
   */

  async close() {
    await this.sdb.close();
  }

  /**
   * Rescan
   */

  async rescan(height, cb) {
    ;
  }

  /**
   * @param {SwapsWallet} - wallet
   */

  registerListing(listing) {
    assert(listing);

    // TODO: here

    // you don't know what height the transaction will
    // be confirmed into a block. it could sit in the
    // mempool for a long time. need a listener for
    // the name getting confirmed in a block.

    const listener = Listener.fromOptions({
      target: targets.CHAIN,
      job: new Job.fromOptions({

      })
    });

    // Create a BLOCK_CONFIRM job in the database and add
    // to a Set that is checked against each block that comes
    // in.
    //
    // This must go in a different db index than height -> joblist
    // name -> null will allow for db.has query which is all
    // that is needed here.
    //
    // When the block containing the TRANSFER is connected
    // to the chain, create a SUBMIT_FINALIZE job in the
    // database at the correct height.
    // need to get current chain height

    // create a job to send finalize after network
    // transfer lockup is complete

    const blockConfirm = Job.fromOptions({
      type: JOB.types.BLOCK_CONFIRM,
      height: this.chain.tip.height,
      data: {
        name: listing.name
      }
    });

    await this.putJob(blockConfirm);

    // create a job to send p2p NAMESWAP message
    // 2 blocks after the finalize is posted
    const broadcast = Job.fromOptions({

    });
  }

  /**
   *
   */

  getNames() {

  }

  /**
   * Returns
   *  - Tip hash
   */

  async getInfo() {
    const tip = await this.sdb.getTip();

    return {
      tip: tip
    };
  }

  /**
   * Get AddrWitness by address.
   * @param {String|hsd.Address} addr
   * @returns {Promise}
   */

  async getAddrWitness(addr) {
    if (typeof addr === 'string')
      addr = Address.fromString(addr);

    return this.sdb.getAddrWitness(addr);
  }

  /**
   * Get all indexed AddrWitnesses.
   * @returns {Promise}
   */

  async getAddrWitnesses() {
    return this.sdb.getAddrWitnesses();
  }


  /**
   *
   */

  async putAddrWitness(addr, addrwitness) {
    const unlock = await this.writeLock.lock();
    try {
      return await this._putAddrWitness(addr, addrwitness);
    } catch (e) {
      debugger;
      this.emit('error', e);
      return null;
    } finally {
      unlock();
    }
  }

  /**
   *
   */

  async _putAddrWitness(addr, witness) {
    if (typeof addr === 'string')
      addr = Address.fromString(addr);

    const addrwitness = AddrWitness.fromAddress(addr, witness, this.network);

    if (!addrwitness.isValid())
      throw new Error('Invalid Witness.');

    return this.sdb.putAddrWitness(addrwitness);
  }

  /**
   * @param {String|Address} - addr
   */

  async hasAddrWitness(addr) {
    if (typeof addr === 'string')
      addr = Address.fromString(addr);

    return this.sdb.hasAddrWitness(addr);
  }

  /**
   * Delete an AddrWitness with a lock.
   */

  async deleteAddrWitness(addr) {
    const unlock = await this.writeLock.lock();
    try {
      return await this._deleteAddrWitness(addr);
    } catch (e) {
      this.emit('error', e);
      return null;
    } finally {
      unlock();
    }
  }

  /**
   * Delete an AddrWitness without a lock
   */

  async _deleteAddrWitness(addr) {
    if (typeof addr === 'string')
      addr = Address.fromString(addr);

    return this.sdb.deleteAddrWitness(addr);
  }

  /**
   *
   */

  async getJobs() {
    return this.sdb.getJobs();
  }

  /**
   *
   */

  /**
   * Some jobs are triggered at a block height.
   * Some jobs are triggered when an event hits
   * the mempool.
   *
   * On bootup, want to getJobs and register them
   * into a Set that waits for the name/output
   * to be included in a block. The relevant
   * things for this are names and pubkeys. So
   * pubkeys are just addresses, maybe could
   * simplify to that.
   *
   */

  async putJob(job) {
    assert(job);

    let height = this.chain.height;

    // need to calculate height that the
    // job will execute at and insert that here.

    switch (job.type) {
      case Job.types.BLOCK_CONFIRM:
        return this.sdb.putJobByName(job);
      case Job.types.SUBMIT_FINALIZE:
      case Job.types.P2PPUBKEY:
      case Job.types.P2PNAMESWAP: {
        return this.sdb.putJobByHeight(job);
      }
      default:
        throw new Error('Unknown Job type.');
    }
  }

  /**
   *
   */

  getJobByName(name) {
    assert(typeof name === 'string');
    return this.sdb.getJobByName(job);
  }

  /**
   *
   */

  getJobByHeight(height) {
    assert(typeof height === 'number');
    return this.sdb.getJobByHeight(job);
  }

  /**
   * Delete the NameSwaps specific index
   */

  async wipe() {
    return this.sdb.wipe();
  }
}

/**
 * Relay Options
 */

// TODO: verify options
class NameSwapsOptions {
  constructor(options) {
    this.network = null;
    this.blocks = null;
    this.chain = null;
    this.memory = false;
    this.prefix = null;
    this.logger = new Logger();

    if (options)
      this.fromOptions(options);
  }

  fromOptions(options) {
    assert(options.spv !== true, 'Cannot run in spv mode.');
    assert(options.pruned !== true, 'Cannot run in pruned mode.');

    assert(options.network);
    this.network = options.network;

    assert(options.chain);
    this.chain = options.chain;

    if (typeof options.memory === 'boolean')
      this.memory = options.memory;

    if (options.logger)
      this.logger = options.logger;

    return this;
  }
}

module.exports = NameSwaps;
