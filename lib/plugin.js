/*!
 * plugin.js - wallet plugin for hsd
 * Copyright (c) 2017-2020, Christopher Jeffrey (MIT License).
 * Copyright (c) 2020, Mark Tyneway (MIT License).
 * https://github.com/handshake-org/hsd
 */

'use strict';

const EventEmitter = require('events');
const NameSwaps = require('./core/nameswaps');
const SwapsWallet = require('./wallet/swapswallet');
const SwapsWalletDB = require('./wallet/swapswalletdb');
const SwapsNetwork = require('./core/swapsnetwork');
const HTTP = require('./core/http');
const WalletHTTP = require('./wallet/http');
const Pool = require('./net/pool');

/**
 * @exports wallet/plugin
 */

const plugin = exports;

/**
 * Plugin
 * @extends EventEmitter
 */

// TODO: assert that this is not a pruned node
class Plugin extends EventEmitter {
  /**
   * Create a plugin.
   * @constructor
   * @param {Node} node
   */

  constructor(node) {
    super();

    this.node = node;
    this.config = node.config.filter('nameswaps');
    this.walletdb = node.require('walletdb');

    // TODO: assert the walletdb plugin is used
    // assert that it is not pruned
    // assert that it is not spv

    this.network = SwapsNetwork(node.network);
    this.logger = node.logger.context('nameswaps');

    this.nameswaps = new NameSwaps({
      network: this.network,
      chain: node.chain,
      logger: this.logger,
      prefix: node.config.getPrefix(),
      memory: this.config.bool('memory', this.node.memory),
      maxFiles: this.config.uint('max-files'),
      cacheSize: this.config.mb('cache-size'),
      spv: this.node.spv
    });

    // TODO: have the default port be internal
    this.pool = new Pool({
      nameswaps: this.nameswaps,
      chain: node.chain,
      network: this.network,
      logger: this.logger,
      listen: this.config.bool('listen'),
      port: this.config.uint('port', this.network.swapsPort),
    });

    /**
     * Keep track of the tip of the chain
     *
     * GET  /nameswaps/wallet
     * GET /nameswaps/wallet/:id/name
     * POST /nameswaps/wallet/:id/name
     *
     * Wallet needs access to this.nameswaps
     * On every block that connects
     */

    this.http = new HTTP({
      network: this.network,
      logger: this.logger,
      node: this.node,
      nameswaps: this.nameswaps,
      pool: this.pool,
      ssl: this.config.bool('ssl'),
      keyFile: this.config.path('ssl-key'),
      certFile: this.config.path('ssl-cert'),
      host: this.config.str('http-host'),
      port: this.config.uint('http-port', this.network.swapsRpcPort),
      apiKey: this.config.str('api-key', node.config.str('api-key')),
      noAuth: this.config.bool('no-auth'),
      cors: this.config.bool('cors')
    });

    this.swdb = new SwapsWalletDB({
      network: this.network,
      logger: this.logger,
      wdb: this.walletdb.wdb,
      //workers: this.node.workers, TODO: see how this is used
      prefix: node.config.getPrefix(),
      memory: this.config.bool('memory', this.node.memory),
      maxFiles: this.config.uint('max-files'),
      cacheSize: this.config.mb('cache-size')
    });

    this.wallethttp = new WalletHTTP({
      network: this.network,
      logger: this.logger,
      node: this.node,
      swdb: this.swdb,
      pool: this.pool,
      wdb: this.walletdb.wdb,
      ssl: this.config.bool('wallet-ssl'),
      keyFile: this.config.path('wallet-ssl-key'),
      certFile: this.config.path('wallet-ssl-cert'),
      host: this.config.str('wallet-http-host'),
      port: this.config.uint('wallet-http-port', this.network.swapsWalletRpcPort),
      apiKey: this.config.str('wallet-api-key', node.config.str('wallet-api-key')),
      noAuth: this.config.bool('wallet-no-auth'),
      cors: this.config.bool('wallet-cors')
    });

    this.init();
  }

  init() {
    this.nameswaps.on('error', err => this.emit('error', err));
    this.swdb.on('error', err => this.emit('error', err));
    this.http.on('error', err => this.emit('error', err));
    this.wallethttp.on('error', err => this.emit('error', err));
  }

  async open() {
    await this.pool.open();
    await this.swdb.open();
    await this.nameswaps.open();
    await this.http.open();
    await this.wallethttp.open();
    await this.pool.connect();
  }

  async close() {
    await this.pool.disconnect();
    await this.swdb.close();
    await this.http.close();
    await this.wallethttp.close();
    await this.nameswaps.close();
    await this.pool.close();
  }
}

/**
 * Plugin name.
 * @const {String}
 */

plugin.id = 'nameswaps';

/**
 * Plugin initialization.
 * @param {Node} node
 * @returns {WalletDB}
 */

plugin.init = function init(node) {
  return new Plugin(node);
};
