/*!
 * http.js - Wallet HTTP endpoints for nameswaps
 * Copyright (c) 2020, Mark Tyneway (Apache-2.0 License).
 * https://github.com/tynes/hsd-nameswaps
 *
 * This software is based on hsd
 * https://github.com/handshake-org/hsd
 * Copyright (c) 2014-2020, Christopher Jeffrey (MIT License).
 *
 * This software is based on bcoin
 * https://github.com/bcoin-org/bcoin
 * Copyright (c) 2014-2015, Fedor Indutny (MIT License)
 * Copyright (c) 2014-2017, Christopher Jeffrey (MIT License).
 * Copyright (c) 2017-2019, bcoin developers (MIT License).
 */

'use strict';

const assert = require('bsert');
const path = require('path');
const {Server} = require('bweb');
const Validator = require('bval');
const random = require('bcrypto/lib/random');
const base58 = require('bcrypto/lib/encoding/base58');
const sha256 = require('bcrypto/lib/sha256');
const Network = require('hsd/lib/protocol/network');
const {BufferSet} = require('buffer-map');
const SwapsWallet = require('../wallet/swapswallet');

/**
 * Initialize HTTP Endpoints.
 */

class HTTP extends Server {
  constructor(options) {
    super(new HTTPOptions(options));

    assert(options.node, 'Must pass node.');
    assert(options.wdb, 'Must pass walletdb');
    assert(options.swdb, 'Must pass SwapsWalletDB');

    this.logger = options.logger.context('swaps-wallet-http');
    this.node = options.node;
    this.nameswaps = options.nameswaps;
    this.wdb = options.wdb;
    this.swdb = options.swdb;
    this.network = options.network;

    this.init();
  }

  init() {
    this.on('request', (req, res) => {
      if (req.method === 'POST' && req.pathname === '/')
        return;

      this.logger.debug('Request for method=%s path=%s (%s).',
        req.method, req.pathname, req.socket.remoteAddress);
    });

    this.on('listening', (address) => {
      this.logger.info('Swaps HTTP server listening on %s (port=%d).',
        address.address, address.port);
    });

    this.initRouter();
    this.initSockets();
  };

  initRouter() {
    if (this.options.cors)
      this.use(this.cors());

    if (!this.options.noAuth) {
      this.use(this.basicAuth({
        hash: sha256.digest,
        password: this.options.apiKey,
        realm: 'node'
      }));
    }

    this.use(this.bodyParser({
      type: 'json'
    }));

    this.use(async (req, res) => {
      if (!this.options.walletAuth) {
        req.admin = true;
        return;
      }

      const valid = Validator.fromRequest(req);
      const token = valid.buf('token');

      if (token && safeEqual(token, this.options.adminToken)) {
        req.admin = true;
        return;
      }

      if (req.method === 'POST' && req.path.length === 0) {
        res.json(403);
        return;
      }
    });

    this.use(this.router());
    this.use(this.jsonRPC(this.node.rpc));

    this.error((err, req, res) => {
      const code = err.statusCode || 500;
      res.json(code, {
        error: {
          type: err.type,
          code: err.code,
          message: err.message
        }
      });
    });

    this.hook(async (req, res) => {
      if (req.path.length < 2)
        return;

      if (req.path[0] !== 'nameswaps' || req.path[1] !== 'wallet')
        return;

      // TODO: is this correct?
      if (req.method === 'PUT' && req.path.length === 2)
        return;

      const valid = Validator.fromRequest(req);
      const id = valid.str('id');
      const token = valid.buf('token');

      if (!id) {
        res.json(403);
        return;
      }

      if (req.admin || !this.options.walletAuth) {
        const wallet = await this.wdb.get(id);

        if (!wallet) {
          res.json(404);
          return;
        }

        req.swapswallet = new SwapsWallet({
          wallet: wallet,
          wdb: this.wdb,
          swdb: this.swdb,
          network: this.network
        });

        return;
      }

      if (!token) {
        res.json(403);
        return;
      }

      let wallet;
      try {
        wallet = await this.wdb.auth(id, token);
      } catch (err) {
        this.logger.info('Auth failure for %s: %s.', id, err.message);
        res.json(403);
        return;
      }

      if (!wallet) {
        res.json(404);
        return;
      }

      req.swapswallet = new SwapsWallet({
        wallet: wallet,
        wdb: this.wdb,
        swdb: this.swdb,
        network: this.network
      });

      this.logger.info('Successful auth for %s.', id);
    });

    // Get key by address
    // This should return the program
    this.get('/nameswaps/wallet/:id/key/:address', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const bech32 = valid.str('address');

      enforce(bech32, 'Address is required.');

      const addr = Address.fromString(bech32, this.network);

      const key = await req.swapwallet.getKey(addr);

      if (!key) {
        res.json(404);
        return;
      }

      res.json(200, key.getJSON(this.network));
    });

    // Create address
    this.post('/nameswaps/wallet/:id/address', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const acct = valid.str('account', 'default');
      const addr = await req.swapswallet.createReceive(acct);

      res.json(200, addr.toJSON());
    });

    // TODO - replace with getAccount i think
    // Get address
    this.get('/nameswaps/wallet/:id/address', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const account = valid.str('account', 'default');
      const branch = valid.str('branch', '0');
      const index = valid.str('index', '0');

    });

    this.get('/nameswaps/wallet/:id/key/:address', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const bech32 = valid.str('address');

      enforce(bech32, 'Address is required.');

      const addr = Address.fromString(bech32, this.network);
      const key = await req.swapswallet.getKey(addr);

      if (!key) {
        res.json(404);
        return;
      }

      res.json(200, key.getJSON(this.network));
    });


    // TODO: refactor below this
    /**
     * Get Wallet Names
     */

    this.get('/nameswaps/wallet/:id/name', async (req, res) => {
      // use walletdb to get owned names, then filter based on
      // names that are swappable
    });

    /**
     * Create a name swap offer
     */

    this.post('/nameswaps/wallet/:id/name/:name/listing', async (req, res) => {
      // name must be owned by wallet
      // spend to the nameswaps template
      // gossip the script preimage and signed txs on the p2p network
      const valid = Validator.fromRequest(req);
      const name = valid.str('name');
      const value = valid.u64('value');

      // TODO: handle error here
      const listing = req.wallet.createListing(name, value);

      // create 2 jobs
      //  - must send FINALIZE transaction after the TRANSFER
      //    transaction is included in a block
      //  - must send P2PNAMESWAP message over the p2p network

      // TODO: the listing should exist in walletdb
      //await this.nameswaps.registerListing(listing);

      // const raw = listing.toInv();
      // encodes the listing in p2p serialization
      // the other side can do Listing.fromInv
      // TODO: define p2p protocol

      // TODO: write the pool, can be a simplified
      // hsd/net/pool, also need the peer
      await this.pool.broadcast(listing.transaction);
    });

    // Proxy non matching requests
    // to wallet http server
    this.use(async (req, res) => {
      await this.wdb.http.routes.handle(req, res);
    });}

  /**
   * Handle new websocket.
    This is called internally when a new
   * websocket connection is attempted.
   * @private
   * @param {WebSocket} socket
   */

  handleSocket(socket) {
    socket.hook('auth', (...args) => {
      if (socket.channel('auth'))
        throw new Error('Already authed.');

      if (!this.options.noAuth) {
        const valid = new Validator(args);
        const key = valid.str(0, '');

        if (key.length > 255)
          throw new Error('Invalid API key.');

        const data = Buffer.from(key, 'ascii');
        const hash = sha256.digest(data);

        if (!safeEqual(hash, this.options.apiHash))
          throw new Error('Invalid API key.');
      }

      socket.join('auth');

      this.logger.info('Successful auth from %s.', socket.host);
      this.handleAuth(socket);

      return null;
    });
  }

  /**
   * Handle new auth'd websocket.
   * This adds hooks. The websocket client
   * must call 'watch witness' to receive events.
   * @private
   * @param {WebSocket} socket
   */

  handleAuth(socket) {
    // TODO
  }

  /**
   * Bind to nameswaps events.
   * Capture emitted events by the
   * nameswaps and send via websocket.
   * @private
   */

  initSockets() {
    // TODO
  }
}

class HTTPOptions {
  /**
   * HTTPOptions
   * @alias module:http.HTTPOptions
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    this.network = Network.primary;
    this.logger = null;
    this.node = null;
    this.wdb = null;
    this.swdb = null;
    this.apiKey = base58.encode(random.randomBytes(20));
    this.apiHash = sha256.digest(Buffer.from(this.apiKey, 'ascii'));
    this.noAuth = false;
    this.cors = false;
    this.maxTxs = 100;

    this.prefix = null;
    this.host = '127.0.0.1';
    this.port = 8080;
    this.ssl = false;
    this.keyFile = null;
    this.certFile = null;

    this.fromOptions(options);
  }

  /**
   * Inject properties from object.
   * @private
   * @param {Object} options
   * @returns {HTTPOptions}
   */

  fromOptions(options) {
    assert(options);
    assert(options.node && typeof options.node === 'object',
      'HTTP Server requires a Node.');
    assert(options.wdb, 'Must pass walletdb');
    assert(options.swdb, 'Must pass SwapsWalletDB');

    this.node = options.node;
    this.wdb = options.wdb;
    this.swdb = options.swdb;

    this.network = options.node.network;
    this.logger = options.node.logger;

    // TODO: fix this
    this.port = this.network.rpcPort;

    if (options.logger != null) {
      assert(typeof options.logger === 'object');
      this.logger = options.logger;
    }

    if (options.apiKey != null) {
      assert(typeof options.apiKey === 'string',
        'API key must be a string.');
      assert(options.apiKey.length <= 255,
        'API key must be under 256 bytes.');
      this.apiKey = options.apiKey;
      this.apiHash = sha256.digest(Buffer.from(this.apiKey, 'ascii'));
    }

    if (options.noAuth != null) {
      assert(typeof options.noAuth === 'boolean');
      this.noAuth = options.noAuth;
    }

    if (options.cors != null) {
      assert(typeof options.cors === 'boolean');
      this.cors = options.cors;
    }

    if (options.prefix != null) {
      assert(typeof options.prefix === 'string');
      this.prefix = options.prefix;
      this.keyFile = path.join(this.prefix, 'key.pem');
      this.certFile = path.join(this.prefix, 'cert.pem');
    }

    if (options.host != null) {
      assert(typeof options.host === 'string');
      this.host = options.host;
    }

    if (options.port != null) {
      assert((options.port & 0xffff) === options.port,
        'Port must be a number.');
      this.port = options.port;
    }

    if (options.ssl != null) {
      assert(typeof options.ssl === 'boolean');
      this.ssl = options.ssl;
    }

    if (options.keyFile != null) {
      assert(typeof options.keyFile === 'string');
      this.keyFile = options.keyFile;
    }

    if (options.certFile != null) {
      assert(typeof options.certFile === 'string');
      this.certFile = options.certFile;
    }

    if (options.maxTxs != null) {
      assert(Number.isSafeInteger(options.maxTxs));
      this.maxTxs = options.maxTxs;
    }

    // Allow no-auth implicitly
    // if we're listening locally.
    if (!options.apiKey) {
      if (this.host === '127.0.0.1' || this.host === '::1')
        this.noAuth = true;
    }

    return this;
  }

  /**
   * Instantiate http options from object.
   * @param {Object} options
   * @returns {HTTPOptions}
   */

  static fromOptions(options) {
    return new HTTPOptions().fromOptions(options);
  }
}

/*
 * Helpers
 */

function enforce(value, msg) {
  if (!value) {
    const err = new Error(msg);
    err.statusCode = 400;
    throw err;
  }
}

/**
 * Expose
 */

module.exports = HTTP;
