/*!
 * peer.js - peer object for hsd
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/hsd
 */

'use strict';

const assert = require('bsert');
const EventEmitter = require('events');
const {Lock} = require('bmutex');
const {format} = require('util');
const tcp = require('btcp');
const dns = require('bdns');
const Logger = require('blgr');
const {RollingFilter} = require('bfilter');
const {BufferMap} = require('buffer-map');
const Parser = require('./parser');
const Framer = require('./framer');
const packets = require('./packets');
const consensus = require('hsd/lib/protocol/consensus');
const common = require('./common');
const InvItem = require('./invitem');
const NetAddress = require('./netaddress');
const Network = require('hsd/lib/protocol/network');
const services = common.services;
const invTypes = InvItem.types;
const packetTypes = packets.types;

/**
 * Represents a network peer.
 * @alias module:net.Peer
 * @extends EventEmitter
 */

class Peer extends EventEmitter {
  /**
   * Create a peer.
   * @alias module:net.Peer
   * @constructor
   * @param {PeerOptions} options
   */

  constructor(options) {
    super();

    this.options = options;
    this.network = this.options.network;
    this.logger = this.options.logger.context('peer');
    this.locker = new Lock();

    this.parser = new Parser(this.network);
    this.framer = new Framer(this.network);

    this.id = -1;
    this.socket = null;
    this.opened = false;
    this.outbound = false;
    this.loader = false;
    this.address = new NetAddress();
    this.local = new NetAddress();
    this.name = null;
    this.connected = false;
    this.destroyed = false;
    this.ack = false;
    this.handshake = false;
    this.time = 0;
    this.lastSend = 0;
    this.lastRecv = 0;
    this.drainSize = 0;
    this.drainQueue = [];
    this.banScore = 0;
    this.invQueue = [];
    this.onPacket = null;

    this.next = null;
    this.prev = null;

    this.version = -1;
    this.services = 0;
    this.height = -1;
    this.agent = null;
    this.noRelay = false;

    this.syncing = false; // TODO(mark): not necessary?
    this.sentAddr = false;
    this.sentGetAddr = false;
    this.challenge = null;
    this.lastPong = -1;
    this.lastPing = -1;
    this.minPing = -1;

    // TODO: I think this is necessary for anything
    // that is on a loop.
    this.addrWitnessTime = -1;

    // Set on a `tip` message
    this.bestHash = consensus.ZERO_HASH;
    this.bestHeight = -1;

    // This is used for initial block download.
    // TODO: switch to using locator for syncing
    // the data, use a bitflag for which data is
    // requested.
    this.lastTip = consensus.ZERO_HASH;
    this.lastStop = consensus.ZERO_HASH;

    this.connectTimeout = null;
    this.pingTimer = null;
    this.invTimer = null;
    this.stallTimer = null;

    this.addrFilter = new RollingFilter(5000, 0.001);
    this.invFilter = new RollingFilter(50000, 0.000001);

    /*
     * TODO: make a filter for programs/swapproofs
    this.addrWitnessFilter = BloomFilter.fromRate(
      20000, 0.001, BloomFilter.flags.ALL);
    */

    this.responseMap = new Map();
    this.syncDataMap = new BufferMap();
    this.totalProofs = 0;

    this.proofWindow = null;
    this.init();
  }

  /**
   * Create inbound peer from socket.
   * @param {PeerOptions} options
   * @param {net.Socket} socket
   * @returns {Peer}
   */

  static fromInbound(options, socket, encrypted) {
    const peer = new this(options);
    peer.accept(socket, encrypted);
    return peer;
  }

  /**
   * Create outbound peer from net address.
   * @param {PeerOptions} options
   * @param {NetAddress} addr
   * @returns {Peer}
   */

  static fromOutbound(options, addr) {
    const peer = new this(options);
    peer.connect(addr);
    return peer;
  }

  /**
   * Create a peer from options.
   * @param {Object} options
   * @returns {Peer}
   */

  static fromOptions(options) {
    return new this(new PeerOptions(options));
  }

  /**
   * Begin peer initialization.
   * @private
   */

  init() {
    this.parser.on('packet', async (packet) => {
      try {
        await this.readPacket(packet);
      } catch (e) {
        this.error(e);
        this.destroy();
      }
    });

    this.parser.on('error', (err) => {
      if (this.destroyed)
        return;

      this.error(err);

      try {
        this.sendReject('malformed', 'error parsing message');
        this.increaseBan(10);
      } catch (e) {
        this.error(e);
      }
    });
  }

  /**
   * Getter to retrieve hostname.
   * @returns {String}
   */

  hostname() {
    return this.address.hostname;
  }

  /**
   * Frame a payload with a header.
   * @param {String} cmd - Packet type.
   * @param {Buffer} payload
   * @returns {Buffer} Payload with header prepended.
   */

  framePacket(cmd, payload) {
    return this.framer.packet(cmd, payload);
  }

  /**
   * Feed data to the parser.
   * @param {Buffer} data
   */

  feedParser(data) {
    return this.parser.feed(data);
  }

  /**
   * Bind to socket.
   * @param {net.Socket} socket
   */

  _bind(socket) {
    assert(!this.socket);

    this.socket = socket;

    this.socket.on('error', (err) => {
      if (!this.connected)
        return;

      this.error(err);
      this.destroy();
    });

    this.socket.once('close', () => {
      this.error('Socket hangup.');
      this.destroy();
    });

    this.socket.on('drain', () => {
      this.handleDrain();
    });

    this.socket.on('data', (chunk) => {
      try {
        this.lastRecv = Date.now();
        this.feedParser(chunk);
      } catch (e) {
        this.error(e);
        this.destroy();
      }
    });

    this.socket.setNoDelay(true);
  }

  /**
   * Accept an inbound socket.
   * @param {net.Socket} socket
   * @returns {net.Socket}
   */

  accept(socket, encrypted) {
    assert(!this.socket);

    this.address = NetAddress.fromSocket(socket, this.network);
    this.address.services = 0;
    this.outbound = false;

    this._bind(socket, encrypted);

    if (encrypted) {
      this.connected = false;
      this.brontide.accept(socket, this.identityKey);
    } else {
      this.time = Date.now();
      this.connected = true;
    }

    return socket;
  }

  /**
   * Create the socket and begin connecting. This method
   * will use `options.createSocket` if provided.
   * @param {NetAddress} addr
   * @returns {net.Socket}
   */

  connect(addr) {
    assert(!this.socket);

    const socket = this.options.createSocket(addr.port, addr.host);

    this.address = addr;
    this.outbound = true;
    this.connected = false;

    this._bind(socket);

    // TODO: need socket.connect here?
    /*
    if (addr.hasKey())
      this.brontide.connect(socket, this.identityKey, addr.key);
    */

    return socket;
  }

  /**
   * Do a reverse dns lookup on peer's addr.
   * @returns {Promise}
   */

  async getName() {
    try {
      if (!this.name) {
        const {host, port} = this.address;
        const {hostname} = await dns.lookupService(host, port);
        this.name = hostname;
      }
    } catch (e) {
      ;
    }
    return this.name;
  }

  /**
   * Open and perform initial handshake (without rejection).
   * @method
   * @returns {Promise}
   */

  async tryOpen() {
    try {
      await this.open();
    } catch (e) {
      ;
    }
  }

  /**
   * Open and perform initial handshake.
   * @method
   * @returns {Promise}
   */

  async open() {
    try {
      await this._open();
    } catch (e) {
      this.error(e);
      this.destroy();
      throw e;
    }
  }

  /**
   * Open and perform initial handshake.
   * @method
   * @returns {Promise}
   */

  async _open() {
    this.opened = true;

    // Connect to peer.
    await this.initConnect();
    await this.initStall();
    await this.initVersion();
    await this.finalize();

    assert(!this.destroyed);

    // Finally we can let the pool know
    // that this peer is ready to go.
    this.emit('open');
  }

  /**
   * Wait for connection.
   * @private
   * @returns {Promise}
   */

  async initConnect() {
    if (this.connected) {
      assert(!this.outbound);
      return Promise.resolve();
    }

    assert(this.socket);

    return new Promise((resolve, reject) => {
      const cleanup = () => {
        if (this.connectTimeout != null) {
          clearTimeout(this.connectTimeout);
          this.connectTimeout = null;
        }

        if (this.socket) {
          // eslint-disable-next-line no-use-before-define
          this.socket.removeListener('error', onError);
        }
      };

      const onError = (err) => {
        cleanup();
        reject(err);
      };

      this.socket.once('connect', () => {
        this.time = Date.now();
        this.connected = true;
        this.emit('connect');

        cleanup();
        resolve();
      });

      this.socket.once('error', onError);

      this.connectTimeout = setTimeout(() => {
        this.connectTimeout = null;
        cleanup();
        reject(new Error('Connection timed out.'));
      }, 10000);
    });
  }

  /**
   * Setup stall timer.
   * @private
   * @returns {Promise}
   */

  initStall() {
    assert(!this.stallTimer);
    assert(!this.destroyed);
    this.stallTimer = setInterval(() => {
      this.maybeTimeout();
    }, Peer.STALL_INTERVAL);
    return Promise.resolve();
  }

  /**
   * Handle post handshake.
   * @method
   * @private
   * @returns {Promise}
   */

  async initVersion() {
    assert(!this.destroyed);

    if (this.outbound) {
      if (this.version !== -1)
        throw new Error('Peer prematurely introduced themselves (outbound).');

      if (this.ack)
        throw new Error('Peer prematurely acknowledged us (outbound).');

      // Say hello.
      this.sendVersion();

      await this.wait(packetTypes.VERACK, 10000);

      assert(this.ack);

      if (this.version === -1)
        await this.wait(packetTypes.VERSION, 10000);

      assert(this.version !== -1);
    } else {
      // We're shy. Wait for an introduction.
      if (this.version === -1)
        await this.wait(packetTypes.VERSION, 10000);

      assert(this.version !== -1);

      if (this.ack)
        throw new Error('Peer prematurely acknowledged us (inbound).');

      this.sendVersion();
    }

    if (this.destroyed)
      throw new Error('Peer was destroyed during handshake.');

    this.handshake = true;

    this.logger.debug('Version handshake complete (%s).', this.hostname());
  }

  /**
   * Finalize peer after handshake.
   * @method
   * @private
   * @returns {Promise}
   */

  async finalize() {
    assert(!this.destroyed);

    // Setup the ping interval.
    this.pingTimer = setInterval(() => {
      this.sendPing();
    }, Peer.PING_INTERVAL);

    // Setup the inv flusher.
    this.invTimer = setInterval(() => {
      this.flushInv();
    }, Peer.INV_INTERVAL);
  }

  announceProgram(programs) {
    if (!this.handshake)
      return;

    if (this.destroyed)
      return;

    if (!Array.isArray(programs))
      programs = [programs];

    const inv = [];

    for (const program of programs) {
      // TODO: fix assertion
      // assert(program instanceof Program);

      // Don't send if they already have it.
      //if (this.invFilter.test(program.hash()))
        //continue;

      inv.push(program.toInv());
    }

    this.queueInv(inv);
  }

  announceSwapProof(proofs) {
    if (!this.handshake)
      return;

    if (this.destroyed)
      return;

    if (!Array.isArray(proofs))
      proofs = [proofs];

    const inv = [];

    // TODO: validation
    // check invFilter
    for (const proof of proofs) {

      inv.push(proof.toInv())
    }

    this.queueInv(inv);
  }


  /**
   * Send inv to a peer.
   * @param {InvItem[]} items
   */

  queueInv(items) {
    if (!this.handshake)
      return;

    if (this.destroyed)
      return;

    if (!Array.isArray(items))
      items = [items];

    for (const item of items) {
      this.invQueue.push(item);
    }

    // TODO(mark): too low?
    if (this.invQueue.length >= 2)
      this.flushInv();
  }

  /**
   * Flush inv queue.
   * @private
   */

  flushInv() {
    if (this.destroyed)
      return;

    const queue = this.invQueue;

    if (queue.length === 0)
      return;

    this.invQueue = [];

    this.logger.spam('Serving %d inv items to %s.',
      queue.length, this.hostname());

    const items = [];

    for (const item of queue) {
      if (!this.invFilter.added(item.data))
        continue;

      items.push(item);
    }

    for (let i = 0; i < items.length; i += 1000) {
      const chunk = items.slice(i, i + 1000);
      this.send(new packets.InvPacket(chunk));
    }
  }

  /**
   * Force send an inv (no filter check).
   * @param {InvItem[]} items
   */

  sendInv(items) {
    if (!this.handshake)
      return;

    if (this.destroyed)
      return;

    if (!Array.isArray(items))
      items = [items];

    for (const item of items)
      this.invFilter.add(item.data);

    if (items.length === 0)
      return;

    this.logger.spam('Serving %d inv items to %s.',
      items.length, this.hostname());

    for (let i = 0; i < items.length; i += 1000) {
      const chunk = items.slice(i, i + 1000);
      this.send(new packets.InvPacket(chunk));
    }
  }

  /**
   * Send a `version` packet.
   * The options.getHeight function is important
   * here, it needs to send the height of the nameswap
   * database tip.
   */

  sendVersion() {
    const packet = new packets.VersionPacket();
    packet.version = this.options.version;
    packet.services = this.options.services;
    packet.time = this.network.now();
    packet.remote = this.address;
    packet.nonce = this.options.createNonce(this.hostname());
    packet.agent = this.options.agent;
    packet.height = this.options.getHeight();
    packet.noRelay = this.options.noRelay;
    this.send(packet);
  }

  /**
   * Send a `sync` packet.
   */

  sendSyncData(start, end) {
    this.send(new packets.SendSyncData(start, stop));
  }

  /**
   * Send a `getaddr` packet.
   */

  sendGetAddr() {
    if (this.sentGetAddr)
      return;

    this.sentGetAddr = true;
    this.send(new packets.GetAddrPacket());
  }

  /**
   * Send a `ping` packet.
   */

  sendPing() {
    if (!this.handshake)
      return;

    if (this.challenge) {
      this.logger.debug(
        'Peer has not responded to ping (%s).',
        this.hostname());
      return;
    }

    this.lastPing = Date.now();
    this.challenge = common.nonce();

    this.send(new packets.PingPacket(this.challenge));
  }

  /**
   * Disconnect from and destroy the peer.
   */

  destroy() {
    const connected = this.connected;

    if (this.destroyed)
      return;

    this.destroyed = true;
    this.connected = false;

    this.socket.destroy();
    this.socket = null;

    if (this.pingTimer != null) {
      clearInterval(this.pingTimer);
      this.pingTimer = null;
    }

    if (this.invTimer != null) {
      clearInterval(this.invTimer);
      this.invTimer = null;
    }

    if (this.stallTimer != null) {
      clearInterval(this.stallTimer);
      this.stallTimer = null;
    }

    if (this.connectTimeout != null) {
      clearTimeout(this.connectTimeout);
      this.connectTimeout = null;
    }

    const jobs = this.drainQueue;

    this.drainSize = 0;
    this.drainQueue = [];

    for (const job of jobs)
      job.reject(new Error('Peer was destroyed.'));

    for (const [cmd, entry] of this.responseMap) {
      this.responseMap.delete(cmd);
      entry.reject(new Error('Peer was destroyed.'));
    }

    this.locker.destroy();

    this.emit('close', connected);
  }

  /**
   * Write data to the peer's socket.
   * @param {Buffer} data
   */

  write(data) {
    if (this.destroyed)
      throw new Error('Peer is destroyed (write).');

    this.lastSend = Date.now();

    if (this.socket.write(data) === false)
      this.needsDrain(data.length);
  }

  /**
   * Send a packet.
   * @param {Packet} packet
   */

  send(packet) {
    if (this.destroyed)
      throw new Error('Peer is destroyed (send).');

    this.sendRaw(packet.type, packet.encode());
    this.addTimeout(packet);
  }

  /**
   * Send a packet.
   * @param {Packet} packet
   */

  sendRaw(type, body) {
    const payload = this.framePacket(type, body);
    this.write(payload);
  }

  /**
   * Wait for a drain event.
   * @returns {Promise}
   */

  drain() {
    if (this.destroyed)
      return Promise.reject(new Error('Peer is destroyed.'));

    if (this.drainSize === 0)
      return Promise.resolve();

    return new Promise((resolve, reject) => {
      this.drainQueue.push({ resolve, reject });
    });
  }

  /**
   * Handle drain event.
   * @private
   */

  handleDrain() {
    const jobs = this.drainQueue;

    this.drainSize = 0;

    if (jobs.length === 0)
      return;

    this.drainQueue = [];

    for (const job of jobs)
      job.resolve();
  }

  /**
   * Add to drain counter.
   * @private
   * @param {Number} size
   */

  needsDrain(size) {
    this.drainSize += size;

    if (this.drainSize >= Peer.DRAIN_MAX) {
      this.logger.warning(
        'Peer is not reading: %dmb buffered (%s).',
        this.drainSize / (1 << 20),
        this.hostname());
      this.error('Peer stalled (drain).');
      this.destroy();
    }
  }

  /**
   * Potentially add response timeout.
   * @private
   * @param {Packet} packet
   *
   * This function is useful for when there is
   * a single type of response for a particular
   * packet sent.
   */

  addTimeout(packet) {
    const timeout = Peer.RESPONSE_TIMEOUT;

    if (!this.outbound)
      return;

    // TODO: add to common the timeouts
    // How does notfound play a role in this?
    //  - GETTIP -> TIP
    //  - GETSYNCDATA -> SYNCDATAACK
    // Things like GETPROGRAM can return NOTFOUND,
    // need to figure out where to handle that

    switch (packet.type) {
      case packetTypes.GETTIP:
        this.request(packetTypes.TIP, timeout);
        break;
      case packetTypes.GETSYNCDATA:
        this.request(packetTypes.GETSYNCDATAACK, timeout);
        break;
      case packetTypes.GETPROGRAM:
        this.request(packetTypes.PROGRAM, timeout);
        break;
      case packetTypes.GETSWAPPROOF:
        this.request(packetTypes.SWAPPROOF, timeout);
        break;
    }
  }

  /**
   * Potentially finish response timeout.
   * @private
   * @param {Packet} packet
   *
   * This function handles the response to a packet
   * that was sent by this peer.
   * The switch statement is for any packet that is
   * a response to GETDATA.
   */

  fulfill(packet) {
    switch (packet.type) {
      case packetTypes.PROGRAM:
      case packetTypes.SWAPPROOF: {
        const entry = this.response(packetTypes.DATA, packet);
        assert(!entry || entry.jobs.length === 0);
        break;
      }
    }

    return this.response(packet.type, packet);
  }

  /**
   * Potentially timeout peer if it hasn't responded.
   * @private
   */

  // TODO: this function needs to be refactored
  maybeTimeout() {
    const now = Date.now();

    for (const [key, entry] of this.responseMap) {
      if (now > entry.timeout) {
        const name = packets.typesByVal[key];
        this.error('Peer is stalling (%s).', name.toLowerCase());
        this.destroy();
        return;
      }
    }

    if (this.loader) {
      // TODO: need a timer for tip/gettip interaction here
      // Send tip message to the loader peer on an interval
      if (now > this.addrWitnessTime + Peer.BLOCK_TIMEOUT) {
        this.error('Peer is stalling (block).');
        this.destroy();
        return;
      }
    }

    for (const time of this.syncData.values()) {
      // TODO: define SYNC_DATA_TIMEOUT
      if (now > time + Peer.SYNC_DATA_TIMEOUT) {
        this.error('Peer is stalling (name).');
        this.destroy();
        return;
      }
    }

    if (now > this.time + 60000) {
      assert(this.time !== 0);

      if (this.lastRecv === 0 || this.lastSend === 0) {
        this.error('Peer is stalling (no message).');
        this.destroy();
        return;
      }

      if (now > this.lastSend + Peer.TIMEOUT_INTERVAL) {
        this.error('Peer is stalling (send).');
        this.destroy();
        return;
      }

      if (now > this.lastRecv + Peer.TIMEOUT_INTERVAL) {
        this.error('Peer is stalling (recv).');
        this.destroy();
        return;
      }

      if (this.challenge && now > this.lastPing + Peer.TIMEOUT_INTERVAL) {
        this.error('Peer is stalling (ping).');
        this.destroy();
        return;
      }
    }
  }

  /**
   * Wait for a packet to be received from peer.
   * @private
   * @param {Number} type - Packet type.
   * @param {Number} timeout
   * @returns {RequestEntry}
   */

  request(type, timeout) {
    if (this.destroyed)
      return null;

    let entry = this.responseMap.get(type);

    if (!entry) {
      entry = new RequestEntry();

      this.responseMap.set(type, entry);

      if (this.responseMap.size >= common.MAX_REQUEST) {
        this.destroy();
        return null;
      }
    }

    entry.setTimeout(timeout);

    return entry;
  }

  /**
   * Fulfill awaiting requests created with {@link Peer#request}.
   * @private
   * @param {Number} type - Packet type.
   * @param {Object} payload
   */

  response(type, payload) {
    const entry = this.responseMap.get(type);

    if (!entry)
      return null;

    this.responseMap.delete(type);

    return entry;
  }

  /**
   * Wait for a packet to be received from peer.
   * @private
   * @param {Number} type - Packet type.
   * @returns {Promise} - Returns Object(payload).
   * Executed on timeout or once packet is received.
   */

  wait(type, timeout) {
    return new Promise((resolve, reject) => {
      const entry = this.request(type);

      if (!entry) {
        reject(new Error('Peer is destroyed (request).'));
        return;
      }

      entry.setTimeout(timeout);
      entry.addJob(resolve, reject);
    });
  }

  /**
   * Emit an error and destroy the peer.
   * @private
   * @param {...String|Error} err
   */

  error(err) {
    if (this.destroyed)
      return;

    if (typeof err === 'string') {
      const msg = format.apply(null, arguments);
      err = new Error(msg);
    }

    if (typeof err.code === 'string' && err.code[0] === 'E') {
      const msg = err.code;
      err = new Error(msg);
      err.code = msg;
      err.message = `Socket Error: ${msg}`;
    }

    err.message += ` (${this.hostname()})`;

    this.emit('error', err);
  }

  /**
   * Send `getdata` to peer.
   * @param {InvItem[]} items
   */

  getData(items) {
    this.send(new packets.GetDataPacket(items));
  }

  /**
   * Send batched `getdata` to peer.
   * @param {InvType} type
   * @param {Hash[]} hashes
   */

  getItems(type, hashes) {
    const items = [];

    for (const hash of hashes)
      items.push(new InvItem(type, hash));

    if (items.length === 0)
      return;

    this.getData(items);
  }

  /**
   * Send batched `getdata` to peer (programs).
   * @param {Hash[]} hashes
   */

  getProgram(hashes) {
    this.getItems(invTypes.PROGRAM, hashes);
  }

  /**
   * Handle a packet payload.
   * @method
   * @private
   * @param {Packet} packet
   */

  async readPacket(packet) {
    if (this.destroyed)
      return;

    // The "pre-handshake" packets get
    // to bypass the lock, since they
    // are meant to change the way input
    // is handled at a low level. They
    // must be handled immediately.
    switch (packet.type) {
      case packetTypes.PONG: {
        try {
          this.socket.pause();
          await this.handlePacket(packet);
        } finally {
          if (!this.destroyed && this.socket) {
            try {
              this.socket.resume();
            } catch (e) {
              ;
            }
          }
        }
        break;
      }
      default: {
        const unlock = await this.locker.lock();
        try {
          this.socket.pause();
          await this.handlePacket(packet);
        } finally {
          if (!this.destroyed && this.socket) {
            try {
              this.socket.resume();
            } catch (e) {
              ;
            }
          }
          unlock();
        }
        break;
      }
    }
  }

  /**
   * Handle a packet payload without a lock.
   * @method
   * @private
   * @param {Packet} packet
   */

  async handlePacket(packet) {
    if (this.destroyed)
      throw new Error('Destroyed peer sent a packet.');

    // If this packet is in response to a sent packet,
    // stop tracking it.
    const entry = this.fulfill(packet);

    switch (packet.type) {
      case packetTypes.VERSION:
        await this.handleVersion(packet);
        break;
      case packetTypes.VERACK:
        await this.handleVerack(packet);
        break;
      case packetTypes.PING:
        await this.handlePing(packet);
        break;
      case packetTypes.PONG:
        await this.handlePong(packet);
        break;
      case packetTypes.GETTIP:
        await this.handleGetTip(packet);
        break;
      case packetTypes.TIP:
        await this.handleTip(packet);
        break;
      case packetTypes.PROGRAM:
        await this.handleProgram(packet);
        break;
      case packetTypes.GETPROGRAM:
        await this.handleGetProgram(packet);

      // TODO(mark): handleInv ?

    }

    if (this.onPacket)
      await this.onPacket(packet);

    this.emit('packet', packet);

    /*
    if (entry)
      entry.resolve(packet);
    */
  }

  /**
   * Handle `version` packet.
   * @method
   * @private
   * @param {VersionPacket} packet
   */

  async handleVersion(packet) {
    if (this.version !== -1)
      throw new Error('Peer sent a duplicate version.');

    this.version = packet.version;
    this.services = packet.services;
    this.height = packet.height;
    this.agent = packet.agent;
    this.noRelay = packet.noRelay;
    this.local = packet.remote;

    if (!this.network.selfConnect) {
      if (this.options.hasNonce(packet.nonce))
        throw new Error('We connected to ourself. Oops.');
    }

    // TODO: need to import MIN_VERSION
    if (this.version < common.MIN_VERSION)
      throw new Error('Peer does not support required protocol version.');

    if (this.outbound) {
      // TODO: need to import services.NETWORK
      if (!(this.services & services.NETWORK))
        throw new Error('Peer does not support network services.');
    }

    this.send(new packets.VerackPacket());
  }

  /**
   * Handle `verack` packet.
   * @method
   * @private
   * @param {VerackPacket} packet
   */

  async handleVerack(packet) {
    if (this.ack) {
      this.logger.debug('Peer sent duplicate ack (%s).', this.hostname());
      return;
    }

    this.ack = true;
    this.logger.debug('Received verack (%s).', this.hostname());
  }

  /**
   * Handle `ping` packet.
   * @method
   * @private
   * @param {PingPacket} packet
   */

  async handlePing(packet) {
    if (!packet.nonce)
      return;

    this.send(new packets.PongPacket(packet.nonce));
  }

  /**
   * Handle `pong` packet.
   * @method
   * @private
   * @param {PongPacket} packet
   */

  async handlePong(packet) {
    const nonce = packet.nonce;
    const now = Date.now();

    if (!this.challenge) {
      this.logger.debug('Peer sent an unsolicited pong (%s).', this.hostname());
      return;
    }

    if (!nonce.equals(this.challenge)) {
      if (nonce.equals(common.ZERO_NONCE)) {
        this.logger.debug('Peer sent a zero nonce (%s).', this.hostname());
        this.challenge = null;
        return;
      }
      this.logger.debug('Peer sent the wrong nonce (%s).', this.hostname());
      return;
    }

    if (now >= this.lastPing) {
      this.lastPong = now;
      if (this.minPing === -1)
        this.minPing = now - this.lastPing;
      this.minPing = Math.min(this.minPing, now - this.lastPing);
    } else {
      this.logger.debug('Timing mismatch (what?) (%s).', this.hostname());
    }

    this.challenge = null;
  }

  handleGetTip(packet) {
    // hmm,
  }

  handleTip(packet) {

  }

  handleGetProgram(packet) {

  }

  handleProgram(packet) {

  }

  handleGetSwapProof() {

  }

  handleSwapProof() {

  }

  sendGetTip(hash) {
    const packet = new packets.GetTipPacket(hash);

    this.logger.debug(
      'Requesting tip packet from peer with gettip (%s).',
      this.hostname());

    this.logger.debug(
      'Sending gettip (hash=%x).',
      hash, stop);

    this.send(packet);
  }

  sendTip() {

  }

  sendGetProgram() {

  }



  /**
   * Send `reject` to peer.
   * @param {Number} code
   * @param {String} reason
   * @param {Number} msg
   * @param {Hash} hash
   */

  sendReject(code, reason, msg, hash) {
    const reject = packets.RejectPacket.fromReason(code, reason, msg, hash);

    if (msg != null) {
      this.logger.debug('Rejecting %s %x (%s): code=%s reason=%s.',
        packets.typesByVal[msg] || 'UNKNOWN',
        hash, this.hostname(), code, reason);
    } else {
      this.logger.debug('Rejecting packet from %s: code=%s reason=%s.',
        this.hostname(), code, reason);
    }

    this.logger.debug(
      'Sending reject packet to peer (%s).',
      this.hostname());

    this.send(reject);
  }

  /**
   * Increase banscore on peer.
   * @param {Number} score
   * @returns {Boolean}
   */

  increaseBan(score) {
    this.banScore += score;

    if (this.banScore >= this.options.banScore) {
      this.logger.debug('Ban threshold exceeded (%s).', this.hostname());
      this.ban();
      return true;
    }

    return false;
  }

  /**
   * Ban peer.
   */

  ban() {
    this.emit('ban');
  }

  /**
   * Send a `reject` packet to peer.
   * @param {Number} msg
   * @param {VerifyError} err
   * @returns {Boolean}
   */

  reject(msg, err) {
    this.sendReject(err.code, err.reason, msg, err.hash);
    return this.increaseBan(err.score);
  }

  /**
   * Test whether required services are available.
   * @param {Number} services
   * @returns {Boolean}
   */

  hasServices(services) {
    return (this.services & services) === services;
  }

  /**
   * Test whether the peer sent us a
   * compatible compact block handshake.
   * @returns {Boolean}
   */

  hasCompact() {
    if (this.compactMode === -1)
      return false;

    return true;
  }

  /**
   * Inspect the peer.
   * @returns {String}
   */

  inspect() {
    return '<Peer:'
      + ` handshake=${this.handshake}`
      + ` host=${this.hostname()}`
      + ` outbound=${this.outbound}`
      + ` ping=${this.minPing}`
      + '>';
  }
}

/**
 * Max output bytes buffered before
 * invoking stall behavior for peer.
 * @const {Number}
 * @default
 */

Peer.DRAIN_MAX = 10 << 20;

/**
 * Interval to check for drainage
 * and required responses from peer.
 * @const {Number}
 * @default
 */

Peer.STALL_INTERVAL = 5000;

/**
 * Interval for pinging peers.
 * @const {Number}
 * @default
 */

Peer.PING_INTERVAL = 30000;

/**
 * Interval to flush invs.
 * Higher means more invs (usually
 * txs) will be accumulated before
 * flushing.
 * @const {Number}
 * @default
 */

Peer.INV_INTERVAL = 5000;

/**
 * Required time for peers to
 * respond to messages (i.e.
 * getblocks/getdata).
 * @const {Number}
 * @default
 */

Peer.RESPONSE_TIMEOUT = 30000;

/**
 * Required time for loader to
 * respond with block/merkleblock.
 * @const {Number}
 * @default
 */

Peer.BLOCK_TIMEOUT = 120000;

/**
 * Required time for loader to
 * respond with a tx.
 * @const {Number}
 * @default
 */

Peer.TX_TIMEOUT = 120000;

/**
 * Required time for peer to
 * respond with a name.
 * @const {Number}
 * @default
 */

Peer.NAME_TIMEOUT = 5000;

/**
 * Generic timeout interval.
 * @const {Number}
 * @default
 */

Peer.TIMEOUT_INTERVAL = 20 * 60000;

/**
 * Peer Options
 * @alias module:net.PeerOptions
 */

class PeerOptions {
  /**
   * Create peer options.
   * @constructor
   */

  constructor(options) {
    this.network = Network.primary;
    this.logger = Logger.global;

    this.createSocket = tcp.createSocket;
    this.version = common.PROTOCOL_VERSION;
    this.services = common.LOCAL_SERVICES;
    this.agent = common.USER_AGENT;
    this.identityKey = common.ZERO_KEY;
    this.noRelay = false;
    this.spv = false;
    this.compact = false;
    this.headers = false;
    this.banScore = common.BAN_SCORE;
    this.proofPRS = 100;

    this.getHeight = PeerOptions.getHeight;
    this.isFull = PeerOptions.isFull;
    this.createNonce = PeerOptions.createNonce;
    this.hasNonce = PeerOptions.hasNonce;
    this.getRate = PeerOptions.getRate;

    if (options)
      this.fromOptions(options);
  }

  /**
   * Inject properties from object.
   * @private
   * @param {Object} options
   * @returns {PeerOptions}
   */

  fromOptions(options) {
    assert(options, 'Options are required.');

    if (options.network != null)
      this.network = Network.get(options.network);

    if (options.logger != null) {
      assert(typeof options.logger === 'object');
      this.logger = options.logger;
    }

    if (options.createSocket != null) {
      assert(typeof options.createSocket === 'function');
      this.createSocket = options.createSocket;
    }

    if (options.version != null) {
      assert(typeof options.version === 'number');
      this.version = options.version;
    }

    if (options.services != null) {
      assert(typeof options.services === 'number');
      this.services = options.services;
    }

    if (options.agent != null) {
      assert(typeof options.agent === 'string');
      this.agent = options.agent;
    }

    if (options.identityKey != null) {
      assert(Buffer.isBuffer(options.identityKey));
      assert(options.identityKey.length === 32);
      this.identityKey = options.identityKey;
    }

    if (options.noRelay != null) {
      assert(typeof options.noRelay === 'boolean');
      this.noRelay = options.noRelay;
    }

    if (options.spv != null) {
      assert(typeof options.spv === 'boolean');
      this.spv = options.spv;
    }

    if (options.compact != null) {
      assert(typeof options.compact === 'boolean');
      this.compact = options.compact;
    }

    if (options.headers != null) {
      assert(typeof options.headers === 'boolean');
      this.headers = options.headers;
    }

    if (options.banScore != null) {
      assert(typeof options.banScore === 'number');
      this.banScore = options.banScore;
    }

    if (options.maxProofRPS != null) {
      assert(typeof options.maxProofRPS === 'number');
      this.maxProofRPS = options.maxProofRPS;
    }

    if (options.getHeight != null) {
      assert(typeof options.getHeight === 'function');
      this.getHeight = options.getHeight;
    }

    if (options.isFull != null) {
      assert(typeof options.isFull === 'function');
      this.isFull = options.isFull;
    }

    if (options.createNonce != null) {
      assert(typeof options.createNonce === 'function');
      this.createNonce = options.createNonce;
    }

    if (options.hasNonce != null) {
      assert(typeof options.hasNonce === 'function');
      this.hasNonce = options.hasNonce;
    }

    if (options.getRate != null) {
      assert(typeof options.getRate === 'function');
      this.getRate = options.getRate;
    }

    return this;
  }

  /**
   * Instantiate options from object.
   * @param {Object} options
   * @returns {PeerOptions}
   */

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  /**
   * Get the chain height.
   * @private
   * @returns {Number}
   */

  static getHeight() {
    return 0;
  }

  /**
   * Test whether the chain is synced.
   * @private
   * @returns {Boolean}
   */

  static isFull() {
    return false;
  }

  /**
   * Create a version packet nonce.
   * @private
   * @param {String} hostname
   * @returns {Buffer}
   */

  static createNonce(hostname) {
    return common.nonce();
  }

  /**
   * Test whether version nonce is ours.
   * @private
   * @param {Buffer} nonce
   * @returns {Boolean}
   */

  static hasNonce(nonce) {
    return false;
  }

  /**
   * Get fee rate for txid.
   * @private
   * @param {Hash} hash
   * @returns {Rate}
   */

  static getRate(hash) {
    return -1;
  }
}

/**
 * Request Entry
 * @ignore
 */

class RequestEntry {
  /**
   * Create a request entry.
   * @constructor
   */

  constructor() {
    this.timeout = 0;
    this.jobs = [];
  }

  addJob(resolve, reject) {
    this.jobs.push({ resolve, reject });
  }

  setTimeout(timeout) {
    this.timeout = Date.now() + timeout;
  }

  reject(err) {
    for (const job of this.jobs)
      job.reject(err);

    this.jobs.length = 0;
  }

  resolve(result) {
    for (const job of this.jobs)
      job.resolve(result);

    this.jobs.length = 0;
  }
}

/*
 * Expose
 */

module.exports = Peer;
