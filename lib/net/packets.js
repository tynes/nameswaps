/*!
 * packets.js - packets for hsd
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/hsd
 */

'use strict';

/**
 * @module net/packets
 */

const assert = require('bsert');
const bio = require('bufio');
const common = require('./common');
const NetAddress = require('./netaddress');
const Program = require('../primitives/program');
const SwapProof = require('../primitives/swapproof');
const InvItem = require('./invitem');
const util = require('../util');
const {encoding} = bio;
const DUMMY = Buffer.alloc(0);
const ZERO_HASH = Buffer.alloc(32);

/**
 * Packet types.
 * @enum {Number}
 * @default
 */

exports.types = {
  VERSION: 0,
  VERACK: 1,
  PING: 2,
  PONG: 3,
  GETADDR: 4,
  ADDR: 5,
  INV: 6,
  GETDATA: 7,
  NOTFOUND: 8,
  GETTIP: 9,
  TIP: 10,
  GETPROGRAM: 11,
  PROGRAM: 12,
  GETSWAPPROOF: 13,
  SWAPPROOF: 14,
  GETDATASYNC: 15,
  DATASYNC: 16,
  REJECT: 17,
  UNKNOWN: 18,
  // Internal
  INTERNAL: 19,
  DATA: 20
};

const types = exports.types;

/**
 * Packet types by value.
 * @const {Object}
 * @default
 */

exports.typesByVal = [
  'VERSION',
  'VERACK',
  'PING',
  'PONG',
  'GETADDR',
  'ADDR',
  'INV',
  'GETDATA',
  'NOTFOUND',
  'GETTIP',
  'TIP',
  'GETPROGRAM',
  'PROGRAM',
  'GETSWAPPROOF',
  'SWAPPROOF',
  'GETDATASYNC',
  'DATASYNC',
  'REJECT',
  'UNKNOWN',
  // Internal
  'INTERNAL',
  'DATA'
];

/**
 * Base Packet
 */

class Packet extends bio.Struct {
  /**
   * Create a base packet.
   * @constructor
   */

  constructor() {
    super();
    this.type = 0;
  }
}

/**
 * Version Packet
 * @extends Packet
 * @property {Number} version - Protocol version.
 * @property {Number} services - Service bits.
 * @property {Number} time - Timestamp of discovery.
 * @property {NetAddress} remote - Their address.
 * @property {Buffer} nonce
 * @property {String} agent - User agent string.
 * @property {Number} height - Chain height.
 * @property {Boolean} noRelay - Whether transactions
 * should be relayed immediately.
 */

class VersionPacket extends Packet {
  /**
   * Create a version packet.
   * @constructor
   * @param {Object?} options
   * @param {Number} options.version - Protocol version.
   * @param {Number} options.services - Service bits.
   * @param {Number} options.time - Timestamp of discovery.
   * @param {NetAddress} options.remote - Their address.
   * @param {Buffer} options.nonce
   * @param {String} options.agent - User agent string.
   * @param {Number} options.height - Chain height.
   * @param {Boolean} options.noRelay - Whether transactions
   * should be relayed immediately.
   */

  constructor(options) {
    super();

    this.type = exports.types.VERSION;

    this.version = common.PROTOCOL_VERSION;
    this.services = common.LOCAL_SERVICES;
    this.time = util.now();
    this.remote = new NetAddress();
    this.nonce = common.ZERO_NONCE;
    this.agent = common.USER_AGENT;
    this.height = 0;
    this.noRelay = false;

    if (options)
      this.fromOptions(options);
  }

  /**
   * Inject properties from options.
   * @private
   * @param {Object} options
   */

  fromOptions(options) {
    if (options.version != null)
      this.version = options.version;

    if (options.services != null)
      this.services = options.services;

    if (options.time != null)
      this.time = options.time;

    if (options.remote)
      this.remote.fromOptions(options.remote);

    if (options.nonce)
      this.nonce = options.nonce;

    if (options.agent)
      this.agent = options.agent;

    if (options.height != null)
      this.height = options.height;

    if (options.noRelay != null)
      this.noRelay = options.noRelay;

    return this;
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    let size = 0;
    size += 20;
    size += this.remote.getSize();
    size += 8;
    size += 1;
    size += this.agent.length;
    size += 5;
    return size;
  }

  /**
   * Write version packet to buffer writer.
   * @param {BufferWriter} bw
   */

  write(bw) {
    bw.writeU32(this.version);
    bw.writeU32(this.services);
    bw.writeU32(0);
    bw.writeU64(this.time);
    this.remote.write(bw);
    bw.writeBytes(this.nonce);
    bw.writeU8(this.agent.length);
    bw.writeString(this.agent, 'ascii');
    bw.writeU32(this.height);
    bw.writeU8(this.noRelay ? 1 : 0);
    return this;
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  read(br) {
    this.version = br.readU32();
    this.services = br.readU32();

    // Note: hi service bits
    // are currently unused.
    br.readU32();

    this.time = br.readU64();
    this.remote.read(br);
    this.nonce = br.readBytes(8);
    this.agent = br.readString(br.readU8(), 'ascii');
    this.height = br.readU32();
    this.noRelay = br.readU8() === 1;

    return this;
  }
}

/**
 * Verack Packet
 * @extends Packet
 */

class VerackPacket extends Packet {
  /**
   * Create a `verack` packet.
   * @constructor
   */

  constructor() {
    super();
    this.type = exports.types.VERACK;
  }
}

/**
 * Ping Packet
 * @extends Packet
 * @property {BN|null} nonce
 */

class PingPacket extends Packet {
  /**
   * Create a `ping` packet.
   * @constructor
   * @param {Buffer} nonce
   */

  constructor(nonce) {
    super();

    this.type = exports.types.PING;

    this.nonce = nonce || common.ZERO_NONCE;
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    return 8;
  }

  /**
   * Serialize ping packet to writer.
   * @param {BufferWriter} bw
   */

  write(bw) {
    bw.writeBytes(this.nonce);
    return this;
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  read(br) {
    this.nonce = br.readBytes(8);
    return this;
  }
}

/**
 * Pong Packet
 * @extends Packet
 * @property {BN} nonce
 */

class PongPacket extends Packet {
  /**
   * Create a `pong` packet.
   * @constructor
   * @param {Buffer} nonce
   */

  constructor(nonce) {
    super();

    this.type = exports.types.PONG;

    this.nonce = nonce || common.ZERO_NONCE;
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    return 8;
  }

  /**
   * Serialize pong packet to writer.
   * @param {BufferWriter} bw
   */

  write(bw) {
    bw.writeBytes(this.nonce);
    return this;
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  read(br) {
    this.nonce = br.readBytes(8);
    return this;
  }
}

/**
 * GetAddr Packet
 * @extends Packet
 */

class GetAddrPacket extends Packet {
  /**
   * Create a `getaddr` packet.
   * @constructor
   */

  constructor() {
    super();
    this.type = exports.types.GETADDR;
  }
}

/**
 * Addr Packet
 * @extends Packet
 * @property {NetAddress[]} items
 */

class AddrPacket extends Packet {
  /**
   * Create a `addr` packet.
   * @constructor
   * @param {(NetAddress[])?} items
   */

  constructor(items) {
    super();

    this.type = exports.types.ADDR;

    this.items = items || [];
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    let size = 0;
    size += encoding.sizeVarint(this.items.length);
    for (const addr of this.items)
      size += addr.getSize();
    return size;
  }

  /**
   * Serialize addr packet to writer.
   * @param {BufferWriter} bw
   */

  write(bw) {
    bw.writeVarint(this.items.length);

    for (const item of this.items)
      item.write(bw);

    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {Buffer} data
   */

  read(br) {
    const count = br.readVarint();

    for (let i = 0; i < count; i++)
      this.items.push(NetAddress.read(br));

    return this;
  }
}

/**
 * Inv Packet
 * @extends Packet
 * @property {InvItem[]} items
 */

class InvPacket extends Packet {
  /**
   * Create a `inv` packet.
   * @constructor
   * @param {(InvItem[])?} items
   */

  constructor(items) {
    super();

    this.type = exports.types.INV;

    this.items = items || [];
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    let size = 0;
    size += encoding.sizeVarint(this.items.length);
    for (const item of this.items)
      size += item.getSize();
    return size;
  }

  /**
   * Serialize inv packet to writer.
   * @param {Buffer} bw
   */

  // TODO: need to import MAX_INV
  write(bw) {
    assert(this.items.length <= common.MAX_INV);

    bw.writeVarint(this.items.length);

    for (const item of this.items)
      item.write(bw);

    return this;
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  read(br) {
    const count = br.readVarint();

    assert(count <= common.MAX_INV, 'Inv item count too high.');

    for (let i = 0; i < count; i++)
      this.items.push(InvItem.read(br));

    return this;
  }
}

/**
 * GetData Packet
 * @extends InvPacket
 */

class GetDataPacket extends InvPacket {
  /**
   * Create a `getdata` packet.
   * @constructor
   * @param {(InvItem[])?} items
   */

  constructor(items) {
    super(items);
    this.type = exports.types.GETDATA;
  }
}

/**
 * NotFound Packet
 * @extends InvPacket
 */

class NotFoundPacket extends InvPacket {
  /**
   * Create a `notfound` packet.
   * @constructor
   * @param {(InvItem[])?} items
   */

  constructor(items) {
    super(items);
    this.type = exports.types.NOTFOUND;
  }
}


/**
 *
 */

class GetTipPacket extends Packet {
  constructor() {
    super();
    this.type = exports.types.GETTIP;
  }
}

/**
 *
 */

class TipPacket extends Packet {
  constructor(hash, height) {
    super();
    this.type = exports.types.TIP;

    this.hash = hash || ZERO_HASH;
    this.height = height || 0;
  }

  getSize() {
    return 36;
  }

  read(br) {
    this.hash = br.readHash();
    this.height = br.readU32();
    return this;
  }

  write(bw) {
    bw.writeHash(this.hash);
    bw.writeU32(this.height);
    return this;
  }
}

/**
 *
 */

class GetProgramPacket extends Packet {
  constructor(hash, index) {
    super();
    this.type = exports.types.GETPROGRAM;

    this.hash = hash || ZERO_HASH;
    this.index = index || 0;
  }

  getSize() {
    return 36;
  }

  read(br) {
    this.hash = br.readHash();
    this.index = br.readU32();
    return this;
  }

  write(bw) {
    bw.writeHash(this.hash);
    bw.writeU32(this.index);
    return this;
  }
}

/**
 *
 */

class ProgramPacket extends GetProgramPacket {
  constructor(program, hash, index) {
    super(hash, index);
    this.type = exports.types.PROGRAM;

    this.program = new Program();
  }

  getSize() {
    let size = 0;
    size += super.getSize();
    size += bio.encoding.sizeVarBytes(this.program.encode());
    return size;
  }

  read(br) {
    super.read(br);
    this.program = Program.decode(br.readVarBytes(), this.hash, this.index);
    return this;
  }

  write(bw) {
    super.write(bw);
    bw.writeVarBytes(this.program.encode());
    return this;
  }

  isNull() {
    // check if

  }
}

/**
 *
 */

class GetSwapProofPacket extends Packet {
  constructor(name) {
    super();
    this.type = exports.types.GETSWAPPROOF;

    this.name = name || '';
  }

  getSize() {
    return bio.encoding.sizeVarString(this.name);
  }

  read(br) {
    this.name = br.readVarString();
    return this;
  }

  write(bw) {
    bw.writeVarString(this.name);
    return this;
  }
}

/**
 *
 */

class SwapProofPacket extends Packet {
  constructor(proof) {
    super();
    this.type = exports.types.SWAPPROOF;

    this.proof = proof || new SwapProof();
  }

  getSize() {
    const proof = this.proof.getSize();
    let size = 0;
    size += bio.encoding.sizeVarint(proof);
    size += proof
    return size;
  }

  read(br) {
    this.proof = SwapProof.decode(br.readVarBytes());
  }

  write(bw) {
    bw.writeVarBytes(this.proof.encode());
  }

  isNull() {

  }
}

/**
 *
 */

class GetDataSyncPacket extends Packet {
  constructor(locator, stop, flags) {
    super();
    this.type = exports.types.GETDATASYNC;

    this.locator = locator || [];
    this.stop = stop || ZERO_HASH;
    this.flags = flags;
  }

  getSize() {
    let size = 0;
    size += bio.encoding.sizeVarint(this.locator.length);
    size += (32 * this.locator.length);
    size += 32;
    size += 4;
    return size;
  }

  read(br) {
    const count = br.readVarint();

    for (let i = 0; i < count; i++)
      this.locator.push(br.readHash());

    this.stop = br.readHash();
    this.flags = br.readU32();
  }

  write(bw) {
    bw.writeVarint(this.locator.length);

    for (const hash of this.locator)
      bw.writeHash(hash);

    bw.writeHash(this.stop);
    bw.writeU32(this.flags);

    return this;
  }
}

GetDataSyncPacket.flags = {
  PROGRAM: 1,
  SWAPPROOF: 1 << 1
};

/**
 *
 */

class DataSyncPacket extends Packet {
  constructor(items, notFound) {
    super();
    this.type = exports.types.DATASYNC;

    this.items = items || [];
    this.notFound = notFound || [];
  }

  getSize() {
    let size = 0;

    size += encoding.sizeVarint(this.items.length);

    for (const item of this.items) {
      size += 1;
      const itemSize = item.getSize();
      size += encoding.sizeVarint(itemSize) + itemSize;
    }

    size += encoding.sizeVarint(this.notFound.length);
    size += 64 * this.notFound.length;
    return size;
  }

  read(br) {
    const resolvedSize = br.readVarint();
    for (let i = 0; i < resolvedSize; i++) {
      const type = br.readU8();
      const packet = br.readVarBytes();
      this.items.push(exports.decode(type, packet))
    }

    const notFoundSize = br.readVarint();
    for (let i = 0; i < notFoundSize; i++) {
      const start = br.readHash();
      const end = br.readHash();
      this.notFound.push([start, end]);
    }

    return this;
  }

  write(bw) {
    assert(this.items.length <= common.MAX_INV);

    bw.writeVarint(this.items.length);
    for (const item of this.items) {
      if (item instanceof ProgramPacket)
        bw.writeU8(exports.types.PROGRAM);
      else if (item instanceof SwapProofPacket)
        bw.writeU8(exports.types.SWAPPROOF)
      else
        bw.writeU8(exports.types.UNKNOWN)

      bw.writeVarBytes(item.encode());
    }

    bw.writeVarint(this.notFound.length);
    for (const [start, end] of this.notFound) {
      bw.writeHash(start);
      bw.writeHash(end);
    }

    return this;
  }
}

/**
 * Reject Packet
 * @extends Packet
 * @property {(Number|String)?} code - Code
 * (see {@link RejectPacket.codes}).
 * @property {String?} msg - Message.
 * @property {String?} reason - Reason.
 * @property {(Hash|Buffer)?} data - Transaction or block hash.
 */

class RejectPacket extends Packet {
  /**
   * Create reject packet.
   * @constructor
   */

  constructor(options) {
    super();

    this.type = exports.types.REJECT;

    this.message = 0;
    this.code = RejectPacket.codes.INVALID;
    this.reason = '';
    this.hash = null;

    if (options)
      this.fromOptions(options);
  }

  /**
   * Inject properties from options object.
   * @private
   * @param {Object} options
   */

  fromOptions(options) {
    let code = options.code;

    if (options.message != null)
      this.message = options.message | 0;

    if (code != null) {
      if (typeof code === 'string')
        code = RejectPacket.codes[code.toUpperCase()];

      if (code >= RejectPacket.codes.INTERNAL)
        code = RejectPacket.codes.INVALID;

      this.code = code;
    }

    if (options.reason)
      this.reason = options.reason;

    if (options.hash)
      this.hash = options.hash;

    return this;
  }

  /**
   * Get symbolic code.
   * @returns {String}
   */

  getCode() {
    const code = RejectPacket.codesByVal[this.code];

    if (!code)
      return this.code.toString(10);

    return code.toLowerCase();
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    let size = 0;

    size += 1;
    size += 1;
    size += 1;
    size += this.reason.length;

    if (this.hash)
      size += 32;

    return size;
  }

  /**
   * Serialize reject packet to writer.
   * @param {BufferWriter} bw
   */

  write(bw) {
    bw.writeU8(this.message);
    bw.writeU8(this.code);
    bw.writeU8(this.reason.length);
    bw.writeString(this.reason, 'ascii');

    if (this.hash)
      bw.writeHash(this.hash);

    return this;
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  // TODO: this is likely wrong
  read(br) {
    this.message = br.readU8();
    this.code = br.readU8();
    this.reason = br.readString(br.readU8(), 'ascii');

    switch (this.message) {
      case types.SWAPPROOF:
        this.hash = br.readHash();
        break;
      case types.PROGRAM:
        this.hash = br.readHash();
        break;
      default:
        this.hash = null;
        break;
    }

    return this;
  }

  /**
   * Inject properties from reason message and object.
   * @private
   * @param {Number} code
   * @param {String} reason
   * @param {String?} msg
   * @param {Hash?} hash
   */

  fromReason(code, reason, msg, hash) {
    if (typeof code === 'string')
      code = RejectPacket.codes[code.toUpperCase()];

    if (!code)
      code = RejectPacket.codes.INVALID;

    if (code >= RejectPacket.codes.INTERNAL)
      code = RejectPacket.codes.INVALID;

    this.message = 0;
    this.code = code;
    this.reason = reason;

    if (msg != null) {
      assert(hash);
      this.message = msg | 0;
      this.hash = hash;
    }

    return this;
  }

  /**
   * Instantiate reject packet from reason message.
   * @param {Number} code
   * @param {String} reason
   * @param {String?} msg
   * @param {Hash?} hash
   * @returns {RejectPacket}
   */

  static fromReason(code, reason, msg, hash) {
    return new this().fromReason(code, reason, msg, hash);
  }

  /**
   * Instantiate reject packet from verify error.
   * @param {VerifyError} err
   * @param {(TX|Block)?} obj
   * @returns {RejectPacket}
   */

  static fromError(err, obj) {
    return this.fromReason(err.code, err.reason, obj);
  }

  /**
   * Inspect reject packet.
   * @returns {String}
   */

  format() {
    const msg = exports.typesByVal[this.message] || 'UNKNOWN';
    const code = RejectPacket.codesByVal[this.code] || this.code;
    const hash = this.hash ? this.hash : null;
    return '<Reject:'
      + ` msg=${msg}`
      + ` code=${code}`
      + ` reason=${this.reason}`
      + ` hash=${hash}`
      + '>';
  }
}

/**
 * Reject codes. Note that `internal` and higher
 * are not meant for use on the p2p network.
 * @enum {Number}
 * @default
 */

RejectPacket.codes = {
  MALFORMED: 0x01,
  INVALID: 0x10,
  // Internal codes (NOT FOR USE ON NETWORK)
  INTERNAL: 0x100,
  HIGHFEE: 0x101,
  ALREADYKNOWN: 0x102,
  CONFLICT: 0x103
};

/**
 * Reject codes by value.
 * @const {Object}
 */

RejectPacket.codesByVal = {
  0x01: 'MALFORMED',
  0x10: 'INVALID',
  // Internal codes (NOT FOR USE ON NETWORK)
  0x100: 'INTERNAL',
  0x101: 'HIGHFEE',
  0x102: 'ALREADYKNOWN',
  0x103: 'CONFLICT'
};

/**
 * Unknown Packet
 * @extends Packet
 * @property {String} cmd
 * @property {Buffer} data
 */

class UnknownPacket extends Packet {
  /**
   * Create an unknown packet.
   * @constructor
   * @param {Number|null} type
   * @param {Buffer|null} data
   */

  constructor(type, data) {
    super();

    this.type = type || types.UNKNOWN;
    this.data = data || DUMMY;
  }

  /**
   * Get serialization size.
   * @returns {Number}
   */

  getSize() {
    return this.data.length;
  }

  /**
   * Serialize unknown packet to writer.
   * @param {BufferWriter} bw
   */

  write(bw) {
    bw.writeBytes(this.data);
    return this;
  }

  /**
   * Inject properties from serialized data.
   * @private
   * @param {BufferReader} data
   * @param {Number} type
   */

  read(br, type) {
    this.data = br.readBytes(br.getSize());
    this.type = type;
    return this;
  }
}

/**
 * Parse a payload.
 * @param {Number} type
 * @param {Buffer} data
 * @returns {Packet}
 */

exports.decode = function decode(type, data) {
  switch (type) {
    case types.VERSION:
      return VersionPacket.decode(data);
    case types.VERACK:
      return VerackPacket.decode(data);
    case types.PING:
      return PingPacket.decode(data);
    case types.PONG:
      return PongPacket.decode(data);
    case types.GETADDR:
      return GetAddrPacket.decode(data);
    case types.ADDR:
      return AddrPacket.decode(data);
    case types.INV:
      return InvPacket.decode(data);
    case types.GETDATA:
      return GetDataPacket.decode(data);
    case types.NOTFOUND:
      return NotFoundPacket.decode(data);
    case types.GETTIP:
      return GetTipPacket.decode(data);
    case types.TIP:
      return TipPacket.decode(data);
    case types.GETPROGRAM:
      return GetProgramPacket.decode(data);
    case types.PROGRAM:
      return ProgramPacket.decode(data);
    case types.GETSWAPPROOF:
      return GetSwapProofPacket.decode(data);
    case types.SWAPPROOF:
      return SwapProofPacket.decode(data);
    case types.GETDATASYNC:
      return GetDataSyncPacket.decode(data);
    case types.DATASYNC:
      return DataSyncPacket.decode(data);
    case types.REJECT:
      return RejectPacket.decode(data);
    default:
      return UnknownPacket.decode(data, type);
  }
};

/*
 * Expose
 */

exports.Packet = Packet;
exports.VersionPacket = VersionPacket;
exports.VerackPacket = VerackPacket;
exports.PingPacket = PingPacket;
exports.PongPacket = PongPacket;
exports.GetAddrPacket = GetAddrPacket;
exports.AddrPacket = AddrPacket;
exports.InvPacket = InvPacket;
exports.GetDataPacket = GetDataPacket;
exports.NotFoundPacket = NotFoundPacket;
exports.GetTipPacket = GetTipPacket;
exports.TipPacket = TipPacket;
exports.GetProgramPacket = GetProgramPacket;
exports.ProgramPacket = ProgramPacket;
exports.GetSwapProofPacket = GetSwapProofPacket;
exports.SwapProofPacket = SwapProofPacket;
exports.GetDataSyncPacket = GetDataSyncPacket;
exports.DataSyncPacket = DataSyncPacket;
exports.RejectPacket = RejectPacket;
exports.UnknownPacket = UnknownPacket;
