/*!
 * pool.js - peer management for hsd
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/hsd
 */

'use strict';

const assert = require('bsert');
const EventEmitter = require('events');
const {Lock} = require('bmutex');
const IP = require('binet');
const dns = require('bdns');
const tcp = require('btcp');
const UPNP = require('bupnp');
const socks = require('bsocks');
const List = require('blst');
const base32 = require('bcrypto/lib/encoding/base32');
const {BufferMap, BufferSet} = require('buffer-map');
const blake2b = require('bcrypto/lib/blake2b');
const {BloomFilter, RollingFilter} = require('bfilter');
const rng = require('bcrypto/lib/random');
const secp256k1 = require('bcrypto/lib/secp256k1');
const {lookup} = require('./lookup');
const util = require('../util');
const common = require('./common');
const Network = require('hsd/lib/protocol/network');
const Peer = require('./peer');
const HostList = require('./hostlist');
const InvItem = require('./invitem');
const packets = require('./packets');
const consensus = require('hsd/lib/protocol/consensus');
// TODO: make sure these exist and are correct
const services = common.services;
const invTypes = InvItem.types;
const packetTypes = packets.types;
const scores = HostList.scores;

// TODO: need HostList
//
// peer connects tcp
// sends version
// counterparty sends verack
// ping pong loop setup on both sides
//
// peer sends gettip to each outbound peer
// waits for tip from each peer
//   includes hash and height
//   updates those properties on the peer
//
// for each block connect
//   send getdatasync to the loader peer
//   wait for getdatasyncack
//   choose new loader peer if too slow
//    or if includes incorrect hash
//
// getsyncdata
//   flags, start hash, end hash
// getsyncdataack
//   flags, h(start hash, end hash), total count
//
// if two getsyncdatas are sent at the same time,
// the second should return a total count of 0
//

/**
 * Pool
 * A pool of peers for handling all network activity.
 * @alias module:net.Pool
 * @extends EventEmitter
 */

class Pool extends EventEmitter {
  /**
   * Create a pool.
   * @constructor
   * @param {Object} options
   */

  constructor(options) {
    super();

    this.opened = false;
    this.options = new PoolOptions(options);

    this.network = this.options.network;
    this.logger = this.options.logger.context('swaps-net');
    this.chain = this.options.chain;

    this.nameswaps = this.options.nameswaps;

    this.server = this.options.createServer();
    this.nonces = this.options.nonces;

    this.locker = new Lock(true, BufferMap);
    this.connected = false;
    this.disconnecting = false;
    this.syncing = false;
    this.discovering = false;

    this.invMap = new BufferMap();
    this.nameMap = new BufferMap();

    this.pendingFilter = null;
    this.refillTimer = null;
    this.discoverTimer = null;
    this.syncTimer = null;

    this.checkpoints = false;

    this.peers = new PeerList();
    this.hosts = new HostList(this.options);
    this.id = 0;

    this.init();
  }

  /**
   * Initialize the pool.
   * @private
   */

  init() {
    this.server.on('error', (err) => {
      this.emit('error', err);
    });

    this.server.on('connection', (socket) => {
      try {
        this.handleSocket(socket);
      } catch (e) {
        this.emit('error', e);
        return;
      }
      this.emit('connection', socket);
    });

    this.server.on('listening', () => {
      const data = this.server.address();
      this.logger.info(
        'Pool server listening on %s (port=%d).',
        data.address, data.port);
      this.emit('listening', data);
    });

    // TODO: index Programs for when addresses
    // are reused. These do not need to be flooded
    // across the network. This should live in NameSwaps
    // module.
    // For each transaction
    //   For each input
    //     if coin.address locks another utxo in utxo set
    //       index Program using witness
    this.chain.on('block', (block, entry) => {
      this.emit('block', block, entry);
    });

    this.chain.on('reset', (tip) => {
      try {
        this.forceSync(tip.hash);
      } catch (e) {
        this.emit('error', e);
      }
    });
  }

  /**
   * Open the pool, wait for the chain to load.
   * @returns {Promise}
   */

  async open() {
    assert(!this.opened, 'Pool is already open.');
    this.opened = true;

    this.logger.info('Pool loaded (maxpeers=%d).', this.options.maxOutbound);
  }

  /**
   * Close and destroy the pool.
   * @method
   * @alias Pool#close
   * @returns {Promise}
   */

  async close() {
    assert(this.opened, 'Pool is not open.');
    this.opened = false;
    return this.disconnect();
  }

  /**
   * Connect to the network.
   * @method
   * @returns {Promise}
   */

  async connect() {
    const unlock = await this.locker.lock();
    try {
      return await this._connect();
    } finally {
      unlock();
    }
  }

  /**
   * Connect to the network (no lock).
   * @method
   * @returns {Promise}
   */

  async _connect() {
    assert(this.opened, 'Pool is not opened.');

    if (this.connected)
      return;

    await this.hosts.open();

    await this.discoverGateway();
    await this.discoverExternal();
    await this.discoverSeeds();

    await this.listen(true);

    this.fillOutbound();

    this.startTimer();

    this.connected = true;
  }

  /**
   * Disconnect from the network.
   * @method
   * @returns {Promise}
   */

  async disconnect() {
    const unlock = await this.locker.lock();
    try {
      return await this._disconnect();
    } finally {
      unlock();
    }
  }

  /**
   * Disconnect from the network.
   * @method
   * @returns {Promise}
   */

  async _disconnect() {
    for (const item of this.invMap.values())
      item.resolve();

    if (!this.connected)
      return;

    this.disconnecting = true;

    this.peers.destroy();

    // TODO:
    // add addrWitnessMap();

    if (this.pendingFilter != null) {
      clearTimeout(this.pendingFilter);
      this.pendingFilter = null;
    }

    this.checkpoints = false;

    this.stopTimer();

    await this.hosts.close();

    await this.unlisten();

    this.disconnecting = false;
    this.syncing = false;
    this.connected = false;
  }

  /**
   * Start listening on a server socket.
   * @method
   * @private
   * @returns {Promise}
   */

  async listen(safe) {
    assert(this.server);

    // Allow decoupling of starting server and
    // attempting to connect to other servers.
    if (safe && this.server.listening)
      return;

    assert(!this.connected, 'Already listening.');

    if (!this.options.listen)
      return;

    this.server.maxConnections = this.options.maxInbound;

    await this.server.listen(this.options.port, this.options.host);
  }

  /**
   * Stop listening on server socket.
   * @method
   * @private
   * @returns {Promise}
   */

  async unlisten() {
    assert(this.server);
    assert(this.connected, 'Not listening.');

    if (!this.options.listen)
      return;

    await this.server.close();
  }

  /**
   * Start discovery timer.
   * @private
   */

  startTimer() {
    assert(this.refillTimer == null, 'Refill timer already started.');
    assert(this.discoverTimer == null, 'Discover timer already started.');
    assert(this.syncTimer == null, 'Sync time already started.');

    this.refillTimer = setInterval(() => this.refill(), Pool.REFILL_INTERVAL);

    this.discoverTimer =
      setInterval(() => this.discover(), Pool.DISCOVERY_INTERVAL);

    this.syncTimer = setInterval(() => this.checkSync(), Pool.CHECK_SYNC_INTERVAL);
  }

  /**
   * Stop discovery timer.
   * @private
   */

  stopTimer() {
    assert(this.refillTimer != null, 'Refill timer already stopped.');
    assert(this.discoverTimer != null, 'Discover timer already stopped.');

    clearInterval(this.refillTimer);
    this.refillTimer = null;

    clearInterval(this.discoverTimer);
    this.discoverTimer = null;

    clearInterval(this.syncTimer);
    this.syncTimer = null;
  }

  /**
   * Rediscover seeds and internet gateway.
   * Attempt to add port mapping once again.
   * @returns {Promise}
   */

  async discover() {
    if (this.discovering)
      return;

    try {
      this.discovering = true;
      await this.discoverGateway();
      await this.discoverSeeds(true);
    } finally {
      this.discovering = false;
    }
  }

  /**
   * Attempt to add port mapping (i.e.
   * remote:8333->local:8333) via UPNP.
   * @returns {Promise}
   */

  async discoverGateway() {
    const src = this.options.publicPort;
    const dest = this.options.port;

    // Pointless if we're not listening.
    if (!this.options.listen)
      return false;

    // UPNP is always optional, since
    // it's likely to not work anyway.
    if (!this.options.upnp)
      return false;

    let wan;
    try {
      this.logger.debug('Discovering internet gateway (upnp).');
      wan = await UPNP.discover();
    } catch (e) {
      this.logger.debug('Could not discover internet gateway (upnp).');
      this.logger.debug(e);
      return false;
    }

    let host;
    try {
      host = await wan.getExternalIP();
    } catch (e) {
      this.logger.debug('Could not find external IP (upnp).');
      this.logger.debug(e);
      return false;
    }

    if (this.hosts.addLocal(host, src, scores.UPNP))
      this.logger.info('External IP found (upnp): %s.', host);

    this.logger.debug(
      'Adding port mapping %d->%d.',
      src, dest);

    try {
      await wan.addPortMapping(host, src, dest);
    } catch (e) {
      this.logger.debug('Could not add port mapping (upnp).');
      this.logger.debug(e);
      return false;
    }

    return true;
  }

  /**
   * Attempt to resolve DNS seeds if necessary.
   * @param {Boolean} checkPeers
   * @returns {Promise}
   */

  async discoverSeeds(checkPeers) {
    if (this.hosts.dnsSeeds.length === 0)
      return;

    const max = Math.min(2, this.options.maxOutbound);
    const size = this.hosts.size();

    let total = 0;
    for (let peer = this.peers.head(); peer; peer = peer.next) {
      if (!peer.outbound)
        continue;

      if (peer.connected) {
        if (++total > max)
          break;
      }
    }

    if (size === 0 || (checkPeers && total < max)) {
      this.logger.warning('Could not find enough peers.');
      this.logger.warning('Hitting DNS seeds...');

      await this.hosts.discoverSeeds();

      this.logger.info(
        'Resolved %d hosts from DNS seeds.',
        this.hosts.size() - size);
    }
  }

  /**
   * Attempt to discover external IP via DNS.
   * @returns {Promise}
   */

  async discoverExternal() {
    const port = this.options.publicPort;

    // Pointless if we're not listening.
    if (!this.options.listen)
      return;

    // Never hit a DNS server if
    // we're using an outbound proxy.
    if (this.options.proxy)
      return;

    // Try not to hit this if we can avoid it.
    if (this.hosts.local.size > 0)
      return;

    let host4 = null;

    try {
      host4 = await dns.getIPv4(2000);
    } catch (e) {
      this.logger.debug('Could not find external IPv4 (dns).');
      this.logger.debug(e);
    }

    if (host4 && this.hosts.addLocal(host4, port, scores.DNS))
      this.logger.info('External IPv4 found (dns): %s.', host4);

    let host6 = null;

    try {
      host6 = await dns.getIPv6(2000);
    } catch (e) {
      this.logger.debug('Could not find external IPv6 (dns).');
      this.logger.debug(e);
    }

    if (host6 && this.hosts.addLocal(host6, port, scores.DNS))
      this.logger.info('External IPv6 found (dns): %s.', host6);
  }

  /**
   * Handle incoming connection.
   * @private
   * @param {net.Socket} socket
   */

  handleSocket(socket) {
    if (!socket.remoteAddress) {
      this.logger.debug('Ignoring disconnected peer.');
      socket.destroy();
      return;
    }

    const ip = IP.normalize(socket.remoteAddress);

    if (this.peers.inbound >= this.options.maxInbound) {
      this.logger.debug('Ignoring peer: too many inbound (%s).', ip);
      socket.destroy();
      return;
    }

    if (this.hosts.isBanned(ip)) {
      this.logger.debug('Ignoring banned peer (%s).', ip);
      socket.destroy();
      return;
    }

    const host = IP.toHostname(ip, socket.remotePort);

    assert(!this.peers.map.has(host), 'Port collision.');

    this.addInbound(socket);
  }

  /**
   * Add a loader peer. Necessary for
   * a sync to even begin.
   * @private
   */

  addLoader() {
    if (!this.opened)
      return;

    assert(!this.peers.load);

    for (let peer = this.peers.head(); peer; peer = peer.next) {
      if (!peer.outbound)
        continue;

      this.logger.info(
        'Repurposing peer for loader (%s).',
        peer.hostname());

      this.setLoader(peer);

      return;
    }

    const addr = this.getHost();

    if (!addr)
      return;

    const peer = this.createOutbound(addr);

    this.logger.info('Adding loader peer (%s).', peer.hostname());

    this.peers.add(peer);

    this.setLoader(peer);
  }

  /**
   * Add a loader peer. Necessary for
   * a sync to even begin.
   * @private
   */

  setLoader(peer) {
    if (!this.opened)
      return;

    assert(peer.outbound);
    assert(!this.peers.load);
    assert(!peer.loader);

    peer.loader = true;
    this.peers.load = peer;

    // TODO:
    // This gets called before creating an outbound peer.
    // Should this happen this way?
    //this.sendGetDataSyncSync(peer);

    this.emit('loader', peer);
  }

  /**
   * Force sending of a sync to each peer.
   */

  forceSync(hash) {
    if (!this.opened)
      return;

    assert(this.connected, 'Pool is not connected!');

    this.resync(hash);
  }

  /**
   * Send a sync to each peer.
   */

  sync() {
    this.resync();
  }

  /**
   * Stop the sync.
   * @private
   */

  stopSync() {
    if (!this.syncing)
      return;

    this.syncing = false;

    for (let peer = this.peers.head(); peer; peer = peer.next) {
      if (!peer.outbound)
        continue;

      if (!peer.syncing)
        continue;

      peer.syncing = false;
      peer.merkleBlock = null;
      peer.merkleTime = -1;
      peer.merkleMatches = 0;
      peer.merkleMap = null;
      peer.blockTime = -1;
      peer.blockMap.clear();
      peer.compactBlocks.clear();
    }

    this.blockMap.clear();
    this.compactBlocks.clear();
  }

  /**
   * Send a sync to each peer.
   * @private
   * @param {Boolean?} force
   * @returns {Promise}
   */

  async resync(hash) {
    if (!this.syncing)
      return;

    if (!hash)
      hash = consensus.ZERO_HASH;

    for (let peer = this.peers.head(); peer; peer = peer.next) {
      if (!peer.outbound)
        continue;

      if (peer.syncing)
        continue;

      // TODO: this is not correct, need getDataSync
      //peer.sendGetTip(hash);
    }
  }

  /**
   *
   */

  checkSync() {
    // TODO: iterate over the peers and check
    // and check to make sure one is syncing
  }

  /**
   * Test whether a peer is sync-worthy.
   * @param {Peer} peer
   * @returns {Boolean}
   */

  isSyncable(peer) {
    /* Need to manage what this.syncing means
     * in this context.
    if (!this.syncing)
      return false;
    */

    if (peer.destroyed)
      return false;

    if (!peer.handshake)
      return false;

    /*
    if (!(peer.services & services.NETWORK))
      return false;
    */

    // If its not the loader peer and
    // the chain isn't synced yet, do
    // not ask other peers for data.
    if (!peer.loader) {
      if (!this.chain.synced)
        return false;
    }

    return true;
  }

  /**
   * Start syncing from peer.
   * @method
   * @param {Peer} peer
   * @returns {Promise}
   */

  async sendGetDataSync(peer, start, end) {
    // It seems like a good idea to not try
    // to request a lot of data while another
    // peer is syncing.
    //if (peer.syncing)
      //return false;

    if (!this.isSyncable(peer))
      return false;

    if (!start) {
      const tip = await this.nameswaps.getTip();
      start = tip.hash;
    }

    if (!end)
      end = this.chain.tip.hash;

    const locator = await this.chain.getLocator(start);

    if (!flags) {
      flags = 0
        | packets.GetDataSync.flags.PROGRAM
        | packets.GetDataSync.flags.SWAPPROOF;
    }

    peer.sendGetDataSync(locator, end, flags);
  }

  /**
   *
   */

  // TODO: isRoutable() ?

  sendGetTip(peer) {
    if (!this.isSyncable(peer))
      return false;

    peer.sendGetTip();
  }

  async sendGetProgram(peer, hash, index) {
    // TODO: validation here?

    peer.sendGetProgram(hash, index);
  }

  async sendGetSwapProof(peer, name) {
    // TODO: validation here?

    peer.sendGetSwapProof(name);
  }


  /**
   * Send `getaddr` to all peers.
   */

  sendGetAddr() {
    for (let peer = this.peers.head(); peer; peer = peer.next)
      peer.sendGetAddr();
  }

  /**
   * Announce broadcast list to peer.
   * @param {Peer} peer
   */

  announceList(peer) {
    const programs = [];
    const swapProofs = [];

    for (const item of this.invMap.values()) {
      switch (item.type) {
        case invTypes.PROGRAM:
          programs.push(item.msg);
          break;
        case invTypes.SWAPPROOF:
          swapProofs.push(item.msg);
          break;
        default:
          assert(false, 'Bad item type.');
          break;
      }
    }

    if (programs.length > 0)
      peer.announceProgram(programs);

    if (swapProofs.length > 0)
      peer.announceSwapProof(swapProofs);
  }

  /**
   * Get a program/swapproof from the broadcast map.
   * @private
   * @param {Peer} peer
   * @param {InvItem} item
   * @returns {Promise}
   */

  getBroadcasted(peer, item) {
    let name = '';
    let type = 0;

    if (item.isProgram()) {
      name = 'program';
      type = invTypes.PROGRAM;
    } else if (item.isSwapProof()) {
      name = 'swapproof';
      type = invTypes.SWAPPROOF;
    }

    const entry = this.invMap.get(item.data);

    if (!entry)
      return null;

    if (type !== entry.type) {
      this.logger.debug(
        'Peer requested item with the wrong type (%s).',
        peer.hostname());
      return null;
    }

    this.logger.debug(
      'Peer requested %s %x (%s).',
      name,
      item.data,
      peer.hostname());

    // TODO: figure out what this does
    entry.handleAck(peer);

    return entry.msg;
  }

  /**
   * Get a block/tx either from the broadcast map, mempool, or blockchain.
   * @method
   * @private
   * @param {Peer} peer
   * @param {InvItem} item
   * @returns {Promise}
   */

  async getItem(peer, item) {
    const entry = this.getBroadcasted(peer, item);

    if (entry)
      return entry;

    if (item.isProgram()) {
      const program = await this.nameswaps.getProgram(item.data);
      if (!program)
        return null;
    }

    if (item.isSwapProof()) {
      const proof = await this.nameswaps.getSwapProof(item.data);
      if (!proof)
        return null;
    }

    return null;
  }

  /**
   * Create an outbound peer with no special purpose.
   * @private
   * @param {NetAddress} addr
   * @returns {Peer}
   */

  createOutbound(addr) {
    const peer = Peer.fromOutbound(this.options, addr);

    this.hosts.markAttempt(addr.hostname);

    this.bindPeer(peer);

    this.logger.debug('Connecting to %s.', peer.hostname());

    peer.tryOpen();

    return peer;
  }

  /**
   * Accept an inbound socket.
   * @private
   * @param {net.Socket} socket
   * @returns {Peer}
   */

  createInbound(socket) {
    const peer = Peer.fromInbound(this.options, socket);

    this.bindPeer(peer);

    peer.tryOpen();

    return peer;
  }

  /**
   * Allocate new peer id.
   * @returns {Number}
   */

  uid() {
    const MAX = Number.MAX_SAFE_INTEGER;

    if (this.id >= MAX - this.peers.size() - 1)
      this.id = 0;

    // Once we overflow, there's a chance
    // of collisions. Unlikely to happen
    // unless we have tried to connect 9
    // quadrillion times, but still
    // account for it.
    do {
      this.id += 1;
    } while (this.peers.find(this.id));

    return this.id;
  }

  /**
   * Bind to peer events.
   * @private
   * @param {Peer} peer
   */

  bindPeer(peer) {
    peer.id = this.uid();

    peer.onPacket = (packet) => {
      return this.handlePacket(peer, packet);
    };

    peer.on('error', (err) => {
      this.logger.debug(err);
    });

    peer.once('connect', async () => {
      try {
        await this.handleConnect(peer);
      } catch (e) {
        this.emit('error', e);
      }
    });

    peer.once('open', async () => {
      try {
        await this.handleOpen(peer);
      } catch (e) {
        this.emit('error', e);
      }
    });

    peer.once('close', async (connected) => {
      try {
        await this.handleClose(peer, connected);
      } catch (e) {
        this.emit('error', e);
      }
    });

    peer.once('ban', async () => {
      try {
        await this.handleBan(peer);
      } catch (e) {
        this.emit('error', e);
      }
    });
  }

  /**
   * Handle peer packet event.
   * @method
   * @private
   * @param {Peer} peer
   * @param {Packet} packet
   * @returns {Promise}
   */

  async handlePacket(peer, packet) {
    switch (packet.type) {
      case packetTypes.VERSION:
        await this.handleVersion(peer, packet);
        break;
      case packetTypes.VERACK:
        await this.handleVerack(peer, packet);
        break;
      case packetTypes.PING:
        await this.handlePing(peer, packet);
        break;
      case packetTypes.PONG:
        await this.handlePong(peer, packet);
        break;
      case packetTypes.GETADDR:
        await this.handleGetAddr(peer, packet);
        break;
      case packetTypes.ADDR:
        await this.handleAddr(peer, packet);
        break;
      case packetTypes.INV:
        await this.handleInv(peer, packet);
        break;
      case packetTypes.GETDATA:
        await this.handleGetData(peer, packet);
        break;
      case packetTypes.NOTFOUND:
        await this.handleNotFound(peer, packet);
        break;
      case packetTypes.GETTIP:
        await this.handleGetTip(peer, packet);
        break;
      case packetTypes.TIP:
        await this.handleTip(peer, packet);
        break;
      case packetTypes.PROGRAM:
        await this.handleProgram(peer, packet);
        break;
      case packetTypes.GETPROGRAM:
        await this.handleGetProgram(peer, packet);
        break;
      case packetTypes.GETSWAPPROOF:
        await this.handleGetSwapProof(peer, packet);
        break;
      case packetTypes.SWAPPROOF:
        await this.handleSwapProof(peer, packet);
        break;
      case packetTypes.GETDATASYNC:
        await this.handleGetDataSync(peer, packet);
        break;
      case packetTypes.DATASYNC:
        await this.handleDataSync(peer, packet);
        break;
      case packetTypes.REJECT:
        await this.handleReject(peer, packet);
        break;
      case packetTypes.UNKNOWN:
        await this.handleUnknown(peer, packet);
        break;
      default:
        assert(false, 'Bad packet type.');
        break;
    }

    this.emit('packet', packet, peer);
  }

  /**
   * Handle peer connect event.
   * @method
   * @private
   * @param {Peer} peer
   */

  async handleConnect(peer) {
    this.logger.info('Connected to %s.', peer.hostname());

    if (peer.outbound)
      this.hosts.markSuccess(peer.hostname());

    this.emit('peer connect', peer);
  }

  /**
   * Handle peer open event.
   * @method
   * @private
   * @param {Peer} peer
   */

  async handleOpen(peer) {
    // Advertise our address.
    if (!this.options.selfish && this.options.listen) {
      const addr = this.hosts.getLocal(peer.address);
      if (addr)
        peer.send(new packets.AddrPacket([addr]));
    }

    // Find some more peers.
    if (!this.hosts.isFull())
      peer.sendGetAddr();

    // TODO: how does the invMap get populated?

    // Announce our currently broadcasted items.
    this.announceList(peer);

    // Get the peers best block
    if (peer.outbound)
      this.sendGetTip(peer);

    if (peer.outbound) {
      this.hosts.markAck(peer.hostname(), peer.services);

      // If we don't have an ack'd
      // loader yet consider it dead.
      if (!peer.loader) {
        if (this.peers.load && !this.peers.load.handshake) {
          assert(this.peers.load.loader);
          this.peers.load.loader = false;
          this.peers.load = null;
        }
      }

      // If we do not have a loader,
      // use this peer.
      if (!this.peers.load)
        this.setLoader(peer);
    }

    this.emit('peer open', peer);

    // TODO: do we still need this?
    this.nameswaps.emit('peer open', peer);
  }

  /**
   * Handle peer close event.
   * @method
   * @private
   * @param {Peer} peer
   * @param {Boolean} connected
   */

  async handleClose(peer, connected) {
    const loader = peer.loader;

    this.removePeer(peer);

    if (loader)
      this.logger.info('Removed loader peer (%s).', peer.hostname());

    this.nonces.remove(peer.hostname());

    this.emit('peer close', peer, connected);

    if (!this.opened)
      return;

    if (this.disconnecting)
      return;

    // TODO:
    // if waiting for a sync response from this peer
    // send a sync to a new peer
  }

  /**
   * Handle ban event.
   * @method
   * @private
   * @param {Peer} peer
   */

  async handleBan(peer) {
    this.ban(peer.address);
    this.emit('ban', peer);
  }

  /**
   * Handle peer version event.
   * @method
   * @private
   * @param {Peer} peer
   * @param {VersionPacket} packet
   */

  async handleVersion(peer, packet) {
    this.logger.info(
      'Received version (%s): version=%d height=%d services=%s agent=%s',
      peer.hostname(),
      packet.version,
      packet.height,
      packet.services.toString(2),
      packet.agent);

    this.network.time.add(peer.hostname(), packet.time);
    this.nonces.remove(peer.hostname());

    if (!peer.outbound && packet.remote.isRoutable())
      this.hosts.markLocal(packet.remote);
  }

  /**
   * Handle `verack` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {VerackPacket} packet
   */

  async handleVerack(peer, packet) {
    ;
  }

  /**
   * Handle `ping` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {PingPacket} packet
   */

  async handlePing(peer, packet) {
    ;
  }

  /**
   * Handle `pong` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {PongPacket} packet
   */

  async handlePong(peer, packet) {
    ;
  }

  /**
   * Handle `getaddr` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {GetAddrPacket} packet
   */

  async handleGetAddr(peer, packet) {
    if (this.options.selfish)
      return;

    if (peer.sentAddr) {
      this.logger.debug(
        'Ignoring repeated getaddr (%s).',
        peer.hostname());
      return;
    }

    peer.sentAddr = true;

    const addrs = this.hosts.toArray();
    const items = [];

    for (const addr of addrs) {
      if (addr.hasKey())
        continue;

      if (!peer.addrFilter.added(addr.hostname, 'ascii'))
        continue;

      items.push(addr);

      if (items.length === 1000)
        break;
    }

    if (items.length === 0)
      return;

    this.logger.debug(
      'Sending %d addrs to peer (%s)',
      items.length,
      peer.hostname());

    peer.send(new packets.AddrPacket(items));
  }

  /**
   * Handle peer addr event.
   * @method
   * @private
   * @param {Peer} peer
   * @param {AddrPacket} packet
   */

  async handleAddr(peer, packet) {
    const addrs = packet.items;
    const now = this.network.now();
    const services = this.options.getRequiredServices();

    for (const addr of addrs) {
      peer.addrFilter.add(addr.hostname, 'ascii');

      if (!addr.isRoutable())
        continue;

      if (!addr.hasServices(services))
        continue;

      if (addr.time <= 100000000 || addr.time > now + 10 * 60)
        addr.time = now - 5 * 24 * 60 * 60;

      if (addr.port === 0)
        continue;

      if (addr.hasKey())
        continue;

      this.hosts.add(addr, peer.address);
    }

    this.logger.info(
      'Received %d addrs (hosts=%d, peers=%d) (%s).',
      addrs.length,
      this.hosts.size(),
      this.peers.size(),
      peer.hostname());

    this.fillOutbound();
  }

  /**
   * Handle `gettip` packet.
   * Should get the tip from nameswaps object.
   * Do not do a database lookup here,
   * that is unsafe.
   */

  async handleGetTip(peer, packet) {
    if (!this.nameswaps.tip)
      return false;
    // TODO:
    // check if routable?

    const {hash, height} = this.nameswaps.tip;

    peer.send(new packets.TipPacket(hash, height));
  }

  /**
   * Handle `tip` packet.
   */

  async handleTip(peer, packet) {
    if (this.debugger)
      debugger;

    if (packet.height < peer.bestHeight)
      this.logger.debug('Peer send lesser height. Before %s, After %s (tip)', peer.bestHeight, packet.height);

    peer.bestHash = packet.hash;
    peer.height = packet.height;
  }

  /**
   * Handle `program` packet.
   * Peer sends a program, it must be checked that
   * it was requested for or that it satisfies an
   * address commitment locking a UTXO that is in
   * the UTXO set. The hash and index must be sent
   * to prevent the need of an address indexer.
   */

  async handleProgram(peer, packet) {
    const program = packet.program;

    if (program.isNull()) {
      this.logger.debug('Program not found (outpoint=%x/%s)',
        program.outpoint.hash, program.outpoint.index);
      peer.increaseBan(1);
      return;
    }

    const coin = await this.chain.getCoin(packet.hash, packet.index);

    if (!coin) {
      this.logger.debug('Unexpected program sent by peer.');
      peer.increaseBan(10);
      return;
    }

    // Verify that the program satisfies the address
    // TODO: make sure there is a toAddress method
    // on the program class.
    const address = program.toAddress();

    if (!address.equals(coin.address)) {
      this.logger.debug('Peer sent bad program.');
      peer.increaseBan(10);
      return;
    }

    await this.nameswaps.putProgram(hash, index, program);
  }

  /**
   * Handle `getprogram` packet.
   * Peer is requesting a program by outpoint.
   * This touches the database so make sure
   * that dos prevention is in place.
   *
   */

  async handleGetProgram(peer, packet) {
    // if (!this.chain.synced)
    //   return;

    const {hash, index} = packet;
    const program = await this.nameswaps.getProgram(hash, index);

    // The program was not found, send a null packet response.
    if (!program) {
      peer.send(new packets.ProgramPacket());
      peer.increaseBan(2);
      return;
    }

    peer.send(new packets.ProgramPacket(program, hash, index));
  }

  /**
   *
   */

  // look up swap proof
  async handleGetSwapProof(peer, packet) {
    const name = packet.name;

    const proof = await this.nameswaps.getSwapProof(name);

    if (!proof) {
      peer.send(new packets.SwapProofPacket());
      peer.increaseBan(2);
      return;
    }

    peer.send(new packets.SwapProofPacket(proof));
  }

  async handleSwapProof(peer, packet) {
    const proof = packet.proof;

    // TODO: make sure the proof is valid

    // if (!proof.verify())
    //   peer.send(new packets.RejectPacket())
    //   peer.increaseBan(20);
    //   return

    await this.nameswaps.putSwapProof(proof.name, proof);
  }

  /**
   *
   *
   */

  async handleGetDataSync(peer, packet) {
    let hash = await this.chain.findLocator(packet.locator);

    if (hash)
      hash = await this.chain.getNextHash(hash);

    const map = new BufferMap();
    const notFound = [];

    while (hash) {
      if (hash.equals(packet.stop))
        break;

      const block = [];

      if (packet.flags & packets.GetDataSyncPacket.flags.PROGRAM) {
        const indexed = await this.getProgramsByBlock(hash);

        for (const program of indexed)
          block.push(program);
      }

      if (packet.flags & packets.GetDataSyncPacket.flags.SWAPPROOF) {
        const indexed = await this.getSwapProofsByBlock(hash);

        for (const proof of indexed)
          block.push(proof);
      }

      if (block.length > 0)
        map.set(hash, block);
      else
        notFound.push(hash);

      hash = await this.chain.getNextHash(hash);
    }

    peer.send(new packets.DataSyncPacket(map, notFound));
  }

  // TODO: here
  async handleDataSync(peer, packet) {
    // packet.items
    // BufferMap
    //   hash: [Packets]
    //   notFound: [hashes]


    for (const [hash, items] of packet.items.entries()) {
      for (const item of items) {
        switch (item.type) {
          case packets.types.SWAPPROOF:
            await this.handleSwapProof(peer, packet);
            break;
          case packets.types.PROGRAM:
            await this.handleProgram(peer, packet);
            break;
          default:
            break;
        }
      }
    }
  }

  /**
   * Handle `inv` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {InvPacket} packet
   */

  async handleInv(peer, packet) {
    const unlock = await this.locker.lock();
    try {
      return await this._handleInv(peer, packet);
    } finally {
      unlock();
    }
  }

  /**
   * Handle `inv` packet (without a lock).
   * @method
   * @private
   * @param {Peer} peer
   * @param {InvPacket} packet
   */

  async _handleInv(peer, packet) {
    const items = packet.items;

    if (items.length > common.MAX_INV) {
      peer.increaseBan(100);
      return;
    }

    // TODO: packet needs to have properties:
    // .items .packet

    const programs = [];
    const swapProofs = [];

    let unknown = -1;

    for (const item of items) {
      switch (item.type) {
        case invTypes.PROGRAM:
          programs.push(item.data);
          continue;
        case invTypes.SWAPPROOF:
          swapProofs.push(item.data);
          continue;
        default:
          unknown = item.type;
          continue;
      }
      peer.invFilter.add(item.data);
    }

    this.logger.spam(
      'Received inv packet with %d items: programs=%d (%s) swapproofs=%d.',
      items.length, programs.length, swapProofs.length, peer.hostname());

    if (unknown !== -1) {
      this.logger.warning(
        'Peer sent an unknown inv type: %d (%s).',
        unknown, peer.hostname());
    }

    if (programs.length > 0)
      await this.handleProgramInv(peer, programs);

    if (swapProofs.length > 0)
      await this.handleSwapProofInv(peer, swapProofs);
  }

  /**
   * Handle `inv` packet from peer (containing only PROGRAM types).
   * @method
   * @private
   * @param {Peer} peer
   * @param {Hash[]} hashes
   * @returns {Promise}
   */

  async handleProgramInv(peer, programs) {
    assert(programs.length > 0);

    // TODO(mark): source from node object?
    if (!this.syncing)
      return;

    // TODO(mark): same as above
    // Ignore for now if we're still syncing
    if (!this.chain.synced && !peer.loader)
      return;

    this.logger.debug(
      'Received %d programs from peer (%s).',
      programs.length,
      peer.hostname());

    const items = [];

    let exists = null;

    // check to see if the program is stored
    // if it is not, request the program

    for (const program of programs) {
      // if the program doesn't exist locally
      // items.push(program);
    }

    // TODO: this isn't defined
    this.getPrograms(peer, items);
  }

  async handleSwapProofInv(peer, program) {
    // check to see if the swap proof is stored
    // if not, request the swap proof
  }

  /**
   * Handle `getdata` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {GetDataPacket} packet
   */

  async handleGetData(peer, packet) {
    const items = packet.items;

    if (items.length > common.MAX_INV) {
      this.logger.warning(
        'Peer sent inv with >50k items (%s).',
        peer.hostname());
      peer.increaseBan(100);
      peer.destroy();
      return;
    }

    const notFound = [];

    let programs = 0;

    for (const item of items) {
      switch (item.type) {
        case invTypes.PROGRAM: {
          const program = await this.getItem(peer, item);

          if (!program) {
            notFound.push(item);
            continue;
          }
          // TODO(mark): prevent sending of anything that
          // would cause the node to get banned here.

          // TODO: also need hash and index...
          // Where do i find that in this context?

          peer.send(new packets.ProgramPacket(program));
          programs += 1;

          continue;
        }

        case invTypes.SWAPPROOF: {
          const proof = await this.getItem(peer, item);

          if (!proof) {
            notFound.push(item);
            continue;
          }

          peer.send(new packets.SwapProofPacket(proof));
          swapProofs += 1;

          continue;
        }

        default: {
          unknown = item.type;
          notFound.push(item);
          continue;
        }
      }

      // Wait for the peer to read
      // before we pull more data
      // out of the database.
      await peer.drain();
    }

    if (notFound.length > 0)
      peer.send(new packets.NotFoundPacket(notFound));

    if (programs > 0) {
      this.logger.debug(
        'Served %d programs with getdata (notfound=%d) (%s).',
        programs, notFound.length, peer.hostname());
    }

    if (unknown !== -1) {
      this.logger.warning(
        'Peer sent an unknown getdata type: %d (%d).',
        unknown, peer.hostname());
    }
  }

  /**
   * Handle peer notfound packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {NotFoundPacket} packet
   */

  async handleNotFound(peer, packet) {
    const items = packet.items;

    // TODO: remove item.hash
    for (const item of items) {
      if (!this.resolveItem(peer, item)) {
        this.logger.warning(
          'Peer sent notfound for unrequested item: %x (%s).',
          item.hash, peer.hostname());
        peer.destroy();
        return;
      }
    }
  }

  /**
   * Log sync status.
   * @private
   * @param {Block} block
   */

  // TODO: update this to make sense in this context
  logStatus(block) {
    if (this.chain.height % 20 === 0) {
      this.logger.debug('Status:'
        + ' time=%s height=%d progress=%s'
        + ' orphans=%d active=%d'
        + ' target=%s peers=%d',
        util.date(block.time),
        this.chain.height,
        (this.chain.getProgress() * 100).toFixed(2) + '%',
        this.chain.orphanMap.size,
        this.blockMap.size,
        block.bits,
        this.peers.size());
    }

    if (this.chain.height % 2000 === 0) {
      this.logger.info(
        'Received 2000 more blocks (height=%d, hash=%x).',
        this.chain.height,
        block.hash());
    }
  }

  /**
   * Handle `unknown` packet.
   * @method
   * @private
   * @param {Peer} peer
   * @param {UnknownPacket} packet
   */

  async handleUnknown(peer, packet) {
    this.logger.warning(
      'Unknown packet: %d (%s).',
      packet.type, peer.hostname());
  }

  /**
   * Create an inbound peer from an existing socket.
   * @private
   * @param {net.Socket} socket
   */

  addInbound(socket) {
    if (!this.opened) {
      socket.destroy();
      return;
    }

    const peer = this.createInbound(socket);

    this.logger.info('Added inbound peer (%s).', peer.hostname());

    this.peers.add(peer);
  }

  /**
   * Allocate a host from the host list.
   * @returns {NetAddress}
   */

  getHost() {
    for (const addr of this.hosts.nodes) {
      if (this.peers.has(addr.hostname))
        continue;

      return addr;
    }

    // TODO(mark): check getRequiredServices method
    // and make sure that it makes sense.
    const services = this.options.getRequiredServices();
    const now = this.network.now();

    for (let i = 0; i < 100; i++) {
      const entry = this.hosts.getHost();

      if (!entry)
        break;

      const addr = entry.addr;

      if (this.peers.has(addr.hostname))
        continue;

      if (this.hosts.local.has(addr.hostname))
        continue;

      if (!addr.isValid())
        continue;

      if (!addr.hasServices(services))
        continue;

      if (!this.options.onion && addr.isOnion())
        continue;

      if (i < 30 && now - entry.lastAttempt < 600)
        continue;

      if (i < 50 && addr.port !== this.network.port)
        continue;

      if (i < 95 && this.hosts.isBanned(addr.host))
        continue;

      return entry.addr;
    }

    return null;
  }

  /**
   * Create an outbound non-loader peer. These primarily
   * exist for transaction relaying.
   * @private
   */

  addOutbound() {
    if (!this.opened)
      return;

    if (this.peers.outbound >= this.options.maxOutbound)
      return;

    // Hang back if we don't
    // have a loader peer yet.
    if (!this.peers.load)
      return;

    const addr = this.getHost();

    if (!addr)
      return;

    const peer = this.createOutbound(addr);

    this.peers.add(peer);

    this.emit('peer', peer);
  }

  /**
   * Attempt to refill the pool with peers (no lock).
   * @private
   */

  fillOutbound() {
    const need = this.options.maxOutbound - this.peers.outbound;

    if (!this.peers.load)
      this.addLoader();

    if (need <= 0)
      return;

    this.logger.spam('Refilling peers (%d/%d).',
      this.peers.outbound,
      this.options.maxOutbound);

    for (let i = 0; i < need; i++)
      this.addOutbound();
  }

  /**
   * Attempt to refill the pool with peers (no lock).
   * @private
   */

  refill() {
    try {
      this.fillOutbound();
    } catch (e) {
      this.emit('error', e);
    }
  }

  /**
   * Remove a peer from any list. Drop all load requests.
   * @private
   * @param {Peer} peer
   */

  // TODO(mark): i think we only need
  // this.resolveAddrWitness
  removePeer(peer) {
    this.peers.remove(peer);

    // TODO: see hsd pool, might need
    // peer.swapProofMap.keys()
  }

  /**
   * Ban peer.
   * @param {NetAddress} addr
   */

  ban(addr) {
    const peer = this.peers.get(addr.hostname);

    this.logger.debug('Banning peer (%s).', addr.hostname);

    this.hosts.ban(addr.host);
    this.hosts.remove(addr.hostname);

    if (peer)
      peer.destroy();
  }

  /**
   * Unban peer.
   * @param {NetAddress} addr
   */

  unban(addr) {
    this.hosts.unban(addr.host);
  }

  /**
   * Reset the spv filter (filterload, SPV-only).
   */

  unwatch() {
    if (!this.options.spv)
      return;

    this.spvFilter.reset();
    this.queueFilterLoad();
  }

  // TODO: some methods for programs and proofs are needed

  /**
   * Fulfill a requested item.
   * @param {Peer} peer
   * @param {InvItem} item
   * @returns {Boolean}
   */

  // TODO(mark): remove addrwitness
  resolveItem(peer, item) {
    if (item.isAddrWitness())
      return this.resolveAddrWitness(peer, item.hash);

    return false;
  }

  /**
   * Broadcast a transaction, block, or claim.
   * @param {InvItem} msg
   * @returns {Promise}
   */

  // TODO: this gets called externally, must be sure
  // that it is correct. The input seems to be polymorphic
  // so add a .hash method that wraps .toKey for Witness class?
  broadcast(msg) {
    const hash = msg.hash();

    let item = this.invMap.get(hash);

    if (item) {
      item.refresh();
      item.announce();
    } else {
      // TODO: update BroadcastItem such that
      // the types are correct.
      item = new BroadcastItem(this, msg);
      item.start();
      item.announce();
    }

    return new Promise((resolve, reject) => {
      item.addJob(resolve, reject);
    });
  }

  announceProgram(msg) {
    for (let peer = this.peers.head(); peer; peer = peer.next)
      peer.announceProgram(msg);
  }

  announceSwapProof(msg) {
    for (let peer = this.peers.head(); peer; peer = peer.next)
      peer.announceSwapProof(msg);
  }
}

/**
 * Interval for refilling outbound peers.
 * @const {Number}
 * @default
 */

Pool.REFILL_INTERVAL = 3000;

/**
 * Discovery interval for UPNP and DNS seeds.
 * @const {Number}
 * @default
 */

Pool.DISCOVERY_INTERVAL = 120000;

/**
 * Discovery interval for p2p syncing
 */

Pool.CHECK_SYNC_INTERVAL = (60000 * 5);

/**
 * Pool Options
 * @alias module:net.PoolOptions
 */

class PoolOptions {
  /**
   * Create pool options.
   * @constructor
   */

  constructor(options) {
    this.network = Network.primary;
    this.logger = null;
    this.chain = null;

    this.nonces = new NonceList();

    // TODO: default options for publicPort

    this.prefix = null;
    this.checkpoints = true;
    this.listen = false;
    this.noRelay = false;
    this.host = '0.0.0.0';
    // TODO: cannot use network.port
    this.port = this.network.port;
    this.publicHost = '0.0.0.0';
    this.publicPort = this.network.port;
    this.maxOutbound = 8;
    this.maxInbound = 8;
    this.createSocket = this._createSocket.bind(this);
    this.createServer = tcp.createServer;
    this.resolve = this._resolve.bind(this);
    this.proxy = null;
    this.onion = false;
    this.upnp = false;
    this.selfish = false;
    this.version = common.PROTOCOL_VERSION;
    // TODO: need to define USER_AGENT
    this.agent = common.USER_AGENT;
    this.authPeers = [];
    this.knownPeers = {};
    this.identityKey = secp256k1.privateKeyGenerate();
    this.banScore = common.BAN_SCORE;
    this.banTime = common.BAN_TIME;
    this.maxProofRPS = 100;
    this.feeRate = -1;

    // TODO: cannot use network.seeds, must add
    // a new list in the decorator
    this.seeds = this.network.seeds;

    this.nodes = [];
    this.invTimeout = 60000;
    this.blockMode = 0;

    // TODO: cannot use services/required services
    this.services = common.LOCAL_SERVICES;
    this.requiredServices = common.REQUIRED_SERVICES;

    this.memory = true;

    this.fromOptions(options);
  }

  /**
   * Inject properties from object.
   * @private
   * @param {Object} options
   * @returns {PoolOptions}
   */

  fromOptions(options) {
    assert(options, 'Pool requires options.');
    assert(options.chain && typeof options.chain === 'object',
      'Pool options require a blockchain.');

    this.chain = options.chain;
    this.network = options.chain.network;
    this.nameswaps = options.nameswaps;
    this.logger = options.chain.logger;

    // TODO: default port
    this.port = this.network.port;
    this.seeds = this.network.seeds;
    this.port = this.network.port;
    this.publicPort = this.network.port;

    if (options.logger != null) {
      assert(typeof options.logger === 'object');
      this.logger = options.logger;
    }

    if (options.mempool != null) {
      assert(typeof options.mempool === 'object');
      this.mempool = options.mempool;
    }

    if (options.prefix != null) {
      assert(typeof options.prefix === 'string');
      this.prefix = options.prefix;
    }

    if (options.checkpoints != null) {
      assert(typeof options.checkpoints === 'boolean');
      assert(options.checkpoints === this.chain.options.checkpoints);
      this.checkpoints = options.checkpoints;
    } else {
      this.checkpoints = this.chain.options.checkpoints;
    }

    if (options.spv != null) {
      assert(typeof options.spv === 'boolean');
      assert(options.spv === this.chain.options.spv);
      this.spv = options.spv;
    } else {
      this.spv = this.chain.options.spv;
    }

    if (options.bip37 != null) {
      assert(typeof options.bip37 === 'boolean');
      this.bip37 = options.bip37;
    }

    if (options.listen != null) {
      assert(typeof options.listen === 'boolean');
      this.listen = options.listen;
    }

    if (options.compact != null) {
      assert(typeof options.compact === 'boolean');
      this.compact = options.compact;
    }

    if (options.noRelay != null) {
      assert(typeof options.noRelay === 'boolean');
      this.noRelay = options.noRelay;
    }

    if (options.host != null) {
      assert(typeof options.host === 'string');
      const raw = IP.toBuffer(options.host);
      this.host = IP.toString(raw);
      if (IP.isRoutable(raw))
        this.publicHost = this.host;
    }

    if (options.port != null) {
      assert((options.port & 0xffff) === options.port);
      this.port = options.port;
      this.publicPort = options.port;
    }

    if (options.publicHost != null) {
      assert(typeof options.publicHost === 'string');
      this.publicHost = IP.normalize(options.publicHost);
    }

    if (options.publicPort != null) {
      assert((options.publicPort & 0xffff) === options.publicPort);
      this.publicPort = options.publicPort;
    }

    if (options.maxOutbound != null) {
      assert(typeof options.maxOutbound === 'number');
      assert(options.maxOutbound > 0);
      this.maxOutbound = options.maxOutbound;
    }

    if (options.maxInbound != null) {
      assert(typeof options.maxInbound === 'number');
      this.maxInbound = options.maxInbound;
    }

    if (options.createSocket) {
      assert(typeof options.createSocket === 'function');
      this.createSocket = options.createSocket;
    }

    if (options.createServer) {
      assert(typeof options.createServer === 'function');
      this.createServer = options.createServer;
    }

    if (options.resolve) {
      assert(typeof options.resolve === 'function');
      this.resolve = options.resolve;
    }

    if (options.proxy) {
      assert(typeof options.proxy === 'string');
      this.proxy = options.proxy;
    }

    if (options.onion != null) {
      assert(typeof options.onion === 'boolean');
      this.onion = options.onion;
    }

    if (options.upnp != null) {
      assert(typeof options.upnp === 'boolean');
      this.upnp = options.upnp;
    }

    if (options.selfish) {
      assert(typeof options.selfish === 'boolean');
      this.selfish = options.selfish;
    }

    if (options.version) {
      assert(typeof options.version === 'number');
      this.version = options.version;
    }

    if (options.agent) {
      assert(typeof options.agent === 'string');
      assert(options.agent.length <= 255);
      this.agent = options.agent;
    }

    if (options.identityKey) {
      assert(Buffer.isBuffer(options.identityKey),
        'Identity key must be a buffer.');
      assert(secp256k1.privateKeyVerify(options.identityKey),
        'Invalid identity key.');
      this.identityKey = options.identityKey;
    }

    if (options.banScore != null) {
      assert(typeof this.options.banScore === 'number');
      this.banScore = this.options.banScore;
    }

    if (options.banTime != null) {
      assert(typeof this.options.banTime === 'number');
      this.banTime = this.options.banTime;
    }

    if (options.maxProofRPS != null) {
      assert(typeof options.maxProofRPS === 'number');
      this.maxProofRPS = options.maxProofRPS;
    }

    if (options.feeRate != null) {
      assert(typeof this.options.feeRate === 'number');
      this.feeRate = this.options.feeRate;
    }

    if (options.seeds) {
      assert(Array.isArray(options.seeds));
      this.seeds = options.seeds;
    }

    if (options.nodes) {
      assert(Array.isArray(options.nodes));
      this.nodes = options.nodes;
    }

    if (options.only != null) {
      assert(Array.isArray(options.only));
      if (options.only.length > 0) {
        this.nodes = options.only;
        this.maxOutbound = options.only.length;
      }
    }

    if (options.invTimeout != null) {
      assert(typeof options.invTimeout === 'number');
      this.invTimeout = options.invTimeout;
    }

    if (options.blockMode != null) {
      assert(typeof options.blockMode === 'number');
      this.blockMode = options.blockMode;
    }

    if (options.memory != null) {
      assert(typeof options.memory === 'boolean');
      this.memory = options.memory;
    }

    if (this.spv) {
      this.requiredServices |= common.services.BLOOM;
      this.services &= ~common.services.NETWORK;
      this.noRelay = true;
      this.checkpoints = true;
      this.compact = false;
      this.bip37 = false;
      this.listen = false;
    }

    if (this.selfish) {
      this.services &= ~common.services.NETWORK;
      this.bip37 = false;
    }

    if (this.bip37)
      this.services |= common.services.BLOOM;

    if (this.proxy)
      this.listen = false;

    if (options.services != null) {
      assert((options.services >>> 0) === options.services);
      this.services = options.services;
    }

    if (options.requiredServices != null) {
      assert((options.requiredServices >>> 0) === options.requiredServices);
      this.requiredServices = options.requiredServices;
    }

    return this;
  }

  /**
   * Instantiate options from object.
   * @param {Object} options
   * @returns {PoolOptions}
   */

  static fromOptions(options) {
    return new PoolOptions().fromOptions(options);
  }

  /**
   * Get the chain height.
   * @private
   * @returns {Number}
   */

  getHeight() {
    if(!this.nameswaps.tip)
      return 0;

    return this.nameswaps.tip.height;
  }

  /**
   * Test whether the chain is synced.
   * @private
   * @returns {Boolean}
   */

  isFull() {
    return this.chain.synced;
  }

  /**
   * Get required services for outbound peers.
   * @private
   * @returns {Number}
   */

  getRequiredServices() {
    return this.requiredServices;
  }

  /**
   * Create a version packet nonce.
   * @private
   * @param {String} hostname
   * @returns {Buffer}
   */

  createNonce(hostname) {
    return this.nonces.alloc(hostname);
  }

  /**
   * Test whether version nonce is ours.
   * @private
   * @param {Buffer} nonce
   * @returns {Boolean}
   */

  hasNonce(nonce) {
    return this.nonces.has(nonce);
  }

  /**
   * Get fee rate for txid.
   * @private
   * @param {Hash} hash
   * @returns {Rate}
   */

  getRate(hash) {
    if (!this.mempool)
      return -1;

    const entry = this.mempool.getEntry(hash);

    if (!entry)
      return -1;

    return entry.getRate();
  }

  /**
   * Default createSocket call.
   * @private
   * @param {Number} port
   * @param {String} host
   * @returns {net.Socket}
   */

  _createSocket(port, host) {
    if (this.proxy)
      return socks.connect(this.proxy, port, host);

    return tcp.createSocket(port, host);
  }

  /**
   * Default resolve call.
   * @private
   * @param {String} name
   * @returns {String[]}
   */

  _resolve(name) {
    if (this.onion)
      return socks.resolve(this.proxy, name);

    return lookup(name);
  }
}

/**
 * Peer List
 * @alias module:net.PeerList
 */

class PeerList {
  /**
   * Create peer list.
   * @constructor
   * @param {Object} options
   */

  constructor() {
    this.map = new Map();
    this.ids = new Map();
    this.list = new List();
    this.load = null;
    this.inbound = 0;
    this.outbound = 0;
  }

  /**
   * Get the list head.
   * @returns {Peer}
   */

  head() {
    return this.list.head;
  }

  /**
   * Get the list tail.
   * @returns {Peer}
   */

  tail() {
    return this.list.tail;
  }

  /**
   * Get list size.
   * @returns {Number}
   */

  size() {
    return this.list.size;
  }

  /**
   * Add peer to list.
   * @param {Peer} peer
   */

  add(peer) {
    assert(this.list.push(peer));

    assert(!this.map.has(peer.hostname()));
    this.map.set(peer.hostname(), peer);

    assert(!this.ids.has(peer.id));
    this.ids.set(peer.id, peer);

    if (peer.outbound)
      this.outbound += 1;
    else
      this.inbound += 1;
  }

  /**
   * Remove peer from list.
   * @param {Peer} peer
   */

  remove(peer) {
    assert(this.list.remove(peer));

    assert(this.ids.has(peer.id));
    this.ids.delete(peer.id);

    assert(this.map.has(peer.hostname()));
    this.map.delete(peer.hostname());

    if (peer === this.load) {
      assert(peer.loader);
      peer.loader = false;
      this.load = null;
    }

    if (peer.outbound)
      this.outbound -= 1;
    else
      this.inbound -= 1;
  }

  /**
   * Get peer by hostname.
   * @param {String} hostname
   * @returns {Peer}
   */

  get(hostname) {
    return this.map.get(hostname);
  }

  /**
   * Test whether a peer exists.
   * @param {String} hostname
   * @returns {Boolean}
   */

  has(hostname) {
    return this.map.has(hostname);
  }

  /**
   * Get peer by ID.
   * @param {Number} id
   * @returns {Peer}
   */

  find(id) {
    return this.ids.get(id);
  }

  /**
   * Destroy peer list (kills peers).
   */

  destroy() {
    let next;

    for (let peer = this.list.head; peer; peer = next) {
      next = peer.next;
      peer.destroy();
    }
  }
}

/**
 * Broadcast Item
 * Represents an item that is broadcasted via an inv/getdata cycle.
 * @alias module:net.BroadcastItem
 * @extends EventEmitter
 * @private
 * @emits BroadcastItem#ack
 * @emits BroadcastItem#reject
 * @emits BroadcastItem#timeout
 */

class BroadcastItem extends EventEmitter {
  /**
   * Create broadcast item.
   * @constructor
   * @param {Pool} pool
   * @param {TX|Block|Claim|AirdropProof} msg
   */

  constructor(pool, msg) {
    super();

    assert(!msg.mutable, 'Cannot broadcast mutable item.');

    const item = msg.toInv();

    this.pool = pool;
    this.hash = item.hash;
    this.type = item.type;
    this.msg = msg;
    this.jobs = [];
  }

  /**
   * Add a job to be executed on ack, timeout, or reject.
   * @returns {Promise}
   */

  addJob(resolve, reject) {
    this.jobs.push({ resolve, reject });
  }

  /**
   * Start the broadcast.
   */

  start() {
    assert(!this.timeout, 'Already started.');

    // What is this.hash?
    assert(!this.pool.invMap.has(this.hash), 'Already started.');

    // TODO: figure this out..
    this.pool.invMap.set(this.hash, this);

    this.refresh();

    return this;
  }

  /**
   * Refresh the timeout on the broadcast.
   */

  refresh() {
    if (this.timeout != null) {
      clearTimeout(this.timeout);
      this.timeout = null;
    }

    this.timeout = setTimeout(() => {
      this.emit('timeout');
      this.reject(new Error('Timed out.'));
    }, this.pool.options.invTimeout);
  }

  /**
   * Announce the item.
   */

  announce() {
    switch (this.type) {
      case invTypes.TX:
        this.pool.announceTX(this.msg);
        break;
      case invTypes.BLOCK:
        this.pool.announceBlock(this.msg);
        break;
      case invTypes.CLAIM:
        this.pool.announceClaim(this.msg);
        break;
      case invTypes.AIRDROP:
        this.pool.announceAirdrop(this.msg);
        break;
      default:
        assert(false, 'Bad type.');
        break;
    }
  }

  /**
   * Finish the broadcast.
   */

  cleanup() {
    assert(this.timeout != null, 'Already finished.');
    assert(this.pool.invMap.has(this.hash), 'Already finished.');

    clearTimeout(this.timeout);
    this.timeout = null;

    this.pool.invMap.delete(this.hash);
  }

  /**
   * Finish the broadcast, return with an error.
   * @param {Error} err
   */

  reject(err) {
    this.cleanup();

    for (const job of this.jobs)
      job.reject(err);

    this.jobs.length = 0;
  }

  /**
   * Finish the broadcast successfully.
   */

  resolve() {
    this.cleanup();

    for (const job of this.jobs)
      job.resolve(false);

    this.jobs.length = 0;
  }

  /**
   * Handle an ack from a peer.
   * @param {Peer} peer
   */

  handleAck(peer) {
    setTimeout(() => {
      this.emit('ack', peer);

      for (const job of this.jobs)
        job.resolve(true);

      this.jobs.length = 0;
    }, 1000);
  }

  /**
   * Handle a reject from a peer.
   * @param {Peer} peer
   */

  handleReject(peer) {
    this.emit('reject', peer);

    for (const job of this.jobs)
      job.resolve(false);

    this.jobs.length = 0;
  }

  /**
   * Inspect the broadcast item.
   * @returns {String}
   */

  inspect() {
    const hash = this.hash;

    let name = '';

    // TODO: this needs to be updated
    switch (this.type) {
      case invTypes.TX:
        name = 'tx';
        break;
      case invTypes.BLOCK:
        name = 'block';
        break;
      case invTypes.CLAIM:
        name = 'claim';
        break;
      case invTypes.AIRDROP:
        name = 'airdrop';
        break;
    }

    return `<BroadcastItem: type=${name} hash=${hash.toString('hex')}>`;
  }
}

/**
 * Nonce List
 * @ignore
 */

class NonceList {
  /**
   * Create nonce list.
   * @constructor
   */

  constructor() {
    this.map = new BufferMap();
    this.hosts = new Map();
  }

  alloc(hostname) {
    for (;;) {
      const nonce = common.nonce();

      if (this.map.has(nonce))
        continue;

      this.map.set(nonce, hostname);

      assert(!this.hosts.has(hostname));
      this.hosts.set(hostname, nonce);

      return nonce;
    }
  }

  has(nonce) {
    return this.map.has(nonce);
  }

  remove(hostname) {
    const nonce = this.hosts.get(hostname);

    if (!nonce)
      return false;

    this.hosts.delete(hostname);

    assert(this.map.has(nonce));
    this.map.delete(nonce);

    return true;
  }
}

/*
 * Helpers
 */

function random(max) {
  return rng.randomRange(0, max);
}

/*
 * Expose
 */

module.exports = Pool;
