/*!
 * invitem.js - inv item object for hsd
 * Copyright (c) 2017-2018, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/hsd
 */

'use strict';

const bio = require('bufio');

/**
 * Inv types.
 * @enum {Number}
 * @default
 */

const types = {
  PROGRAM: 1,
  SWAPPROOF: 2
};

/**
 * Inv types by value.
 * @const {Object}
 */

const typesByVal = {
  1: 'PROGRAM',
  2: 'SWAPPROOF'
};

/**
 * Inv Item
 * @alias module:primitives.InvItem
 * @constructor
 * @property {InvType} type
 * @property {Buffer} data
 */

class InvItem extends bio.Struct {
  /**
   * Create an inv item.
   * @constructor
   * @param {Number} type
   * @param {Buffer} data
   */

  constructor(type, data) {
    super();
    this.type = type;
    this.data = data;
  }

  /**
   * Get size of raw InvItem
   */

  // TODO: this might be wrong
  getSize() {
    return 1 + bio.encoding.sizeVarBytes(this.data);
  }

  /**
   * Write inv item to buffer writer.
   * @param {BufferWriter} bw
   */

  write(bw) {
    bw.writeU8(this.type);
    bw.writeVarBytes(this.data);
    return this;
  }

  /**
   * Inject properties from buffer reader.
   * @private
   * @param {BufferReader} br
   */

  read(br) {
    this.type = br.readU8();
    this.data = br.readVarBytes();
    return this;
  }

  isProgram() {
    return this.type === types.PROGRAM;
  }

  isSwapProof() {
    return this.type === types.SWAPPROOF;
  }
}

InvItem.types = types;
InvItem.typesByVal = typesByVal;

/*
 * Expose
 */

module.exports = InvItem;
