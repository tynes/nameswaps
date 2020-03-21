/*!
 * http.js - HTTP endpoints for nameswaps
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
 * Extends the hsd HTTP endpoints with
 * a new base path /nameswaps
 *
 * GET /nameswaps
 * GET /nameswaps/program/:hash/:index
 * POST /nameswaps/program
 *
 * GET /nameswaps/block/program/:hash
 *
 * GET /nameswaps/name
 *
 * GET /nameswaps/peer
 * POST /namewaps/peer
 * DELETE /nameswaps/peer/:id
 */

// TODO: figure out the jobs stuff
// TODO: figure out how to index programs/proof by
// block hash

class HTTP extends Server {
  constructor(options) {
    super(new HTTPOptions(options));

    assert(options.node, 'Must pass node.');
    assert(options.nameswaps, 'Must pass nameswaps.');

    this.node = options.node;
    this.nameswaps = options.nameswaps;

    this.nameswaps = options.nameswaps;
    this.logger = options.logger;

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

    /**
     * Get Nameswaps Info.
     */

    this.get('/nameswaps', async (req, res) => {
      const info = await this.nameswaps.getInfo();

      if (!info) {
        res.json(400);
        return;
      }

      res.json(200, info);
    });

    /**
     * Get all SwapProofs
     */

    this.get('/nameswaps/name', async (req, res) => {
      const proofs = await this.nameswaps.getSwapProofs();

      if (!proofs) {
        res.json(400);
        return;
      }

      const json = [];
      for (const proof of proofs)
        json.push(proof.toJSON());

      res.json(200, json);
    });

    /**
     * Get SwapProof by name
     */

    this.get('/nameswaps/name/:name', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const name = valid.str('name');

      enforce(name, 'Must pass name.');

      const proof = await this.nameswaps.getSwapProof(name);

      if (!proof) {
        res.json(404);
        return;
      }

      res.json(200, proof.toJSON());
    });

    /**
     *
     */

    this.get('/nameswaps/program', async (req, res) => {
      const programs = await this.nameswaps.getPrograms();

      if (!programs) {
        res.json(400);
        return;
      }

      const json = [];
      for (const program of programs)
        json.push(program.toJSON());

      res.json(200, json);
    });

    /**
     *
     */

    this.get('/nameswaps/program/:hash/:index', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const hash = valid.buf('hash');
      const index = valid.uint('index');

      enforce(hash, 'Must pass hash.');
      enforce(index, 'Must pass index.');

      const program = await this.nameswaps.getProgram(hash, index);

      if (!program) {
        res.json(404);
        return;
      }

      res.json(200, program.toJSON());
    });

    /**
     *
     */

    this.post('/nameswaps/program', async (req, res) => {
      const valid = Validator.fromRequest(req);
      let program = valid.obj('program');
      const hash = valid.buf('hash');
      const index = valid.uint('index');

      enforce(program, 'Must pass program.');
      enforce(hash, 'Must pass hash.');
      enforce(index, 'Must pass index.');

      try {
        program = Program.fromJSON(program);
      } catch (e) {
        enforce(false, 'Invalid Program.');
        return;
      }

      // TODO: abstract this into the nameswaps class
      const coin = await this.node.chain.db.getCoin(hash, index);

      if (!coin)
        enforce(false, 'Coin not found.');

      if (coin.address.isPubkeyhash()) {
        enforce()
        const address = Address.fromPubkey(program)

      }

      if (coin.address.isScripthash()) {
        const address = Address.fromScripthash(program)
      }

    });

    /**
     * Get Programs and/or SwapProofs by block hash
     */

    this.get('/nameswaps/block/:hash', async (req, res) => {
      const valid = Validator.fromRequest(req);
      const hash = valid.buf('hash');
      const programs = valid.bool('programs');
      const swapproofs = valid.bool('swapproofs');

      enforce(hash, 'Must pass hash.');
      enforce(programs || swapproofs, 'Must send programs or swapproofs.');

      const result = {
        programs: [],
        swapproofs: []
      };

      if (programs) {
        const progs = await this.nameswaps.getProgramsByBlock(hash);

        if (!progs) {
          res.json(400);
          return;
        }

        for (const prog of progs)
          result.programs.push(prog.toJSON());
      }

      if (swapproofs) {
        const proofs = await this.nameswaps.getSwapProofsByBlock(hash);

        if (!proofs) {
          res.json(400);
          return;
        }

        for (const proof of proofs)
          result.swapproofs.push(proof.toJSON());
      }

      res.json(200, result);
    });

    // TODO: figure this out...
    // allow to be flexible enough to POST sending
    // an arbitrary tx at an arbitrary height
    this.get('/nameswaps/jobs', async (req, res) => {
      const jobs = await this.nameswaps.getJobs();

      if (!jobs) {
        res.json(400);
        return;
      }

      res.json(200, jobs);
    });

  }

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
    socket.hook('watch nameswaps', () => {
      socket.join('nameswaps');
      return null;
    });

    socket.hook('unwatch nameswaps', () => {
      socket.leave('nameswaps');
      return null;
    });
  }

  /**
   * Bind to nameswaps events.
   * Capture emitted events by the
   * nameswaps and send via websocket.
   * @private
   */

  initSockets() {
    // TODO: figure out the correct events
    // that need to be broadcasted
    this.nameswaps.on('witness', (data) => {
      const sockets = this.channel('nameswaps');

      if (!sockets)
        return;

      // TODO: think about the channels here
      this.to('nameswaps', 'new witness', data);
    });
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

    this.node = options.node;
    this.network = options.node.network;
    this.logger = options.node.logger;

    // TODO: check to make sure this is correct
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
