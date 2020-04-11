/**
 *
 */

// TODO: move this to the wallet
const bio = require('bufio');
const assert = require('bsert');
const Address = require('hsd/lib/primitives/address');

'use strict';

/**
 * Jobs are saved in the database
 * blockheight -> JobList
 *
 * Mempool listening
 * name -> Job
 *
 */

const types = {
  SUBMIT_FINALIZE: 0,
  BLOCK_CONFIRM: 1,
  P2PPUBKEY: 2,
  P2PNAMESWAP: 3
};

const typesByVal = {
  [types.SUBMIT_FINALIZE]: 'SUBMIT_FINALIZE',
  [types.BLOCK_CONFIRM]: 'BLOCK_CONFIRM',
  [types.P2PPUBKEY]: 'P2PPUBKEY',
  [types.P2PNAMESWAP]: 'P2PNAMESWAP'
};

// TODO: this serialization seems too complex
// Maybe have multiple indexes for height -> type of job
// Then inherit from job the different types.

// define null values instead of null
// so that it can be serialized without
// a problem.

class Job extends bio.Struct {
  constructor(options) {
    super();

    this.height = 0;
    this.type = null;

    this.data = {
      name: null,
      pubkey: null,
      signature: null,
      value: null,
      address: null
    };

    if (options)
      this.fromOptions(options)
  }

  fromOptions(options) {
    if (typeof options.height === 'number') {
      assert((options.height >>> 0) === options.height);
      this.height = options.height;
    }

    if (typeof options.type === 'number') {
      assert(options.type in typesByVal);
      this.type = options.type;
    }

    // TODO: verify options based on type
    if (options.data != null) {
      if (this.type === types.P2PPUBKEY)
        assert(Buffer.isBuffer(options.data.pubkey));

      if (this.type === types.P2PNAMESWAP) {
        assert(Buffer.isBuffer(options.data.pubkey));
      }

      this.data = options.data;
    }

    return this;
  }

  inject(job) {

  }

  read(br, height) {
    this.type = br.readU8();

    if (this.type === types.SUBMIT_FINALIZE)
      this.readSubmitFinalize(br);
    else if (type.type === types.BLOCK_CONFIRM)
      this.readBlockConfirm(br);
    else if (this.type === types.P2PNAMESWAP)
      this.readP2PNameSwap(br);
    else if (this.type === types.P2PPUBKEY)
      this.readP2PPubkey(br);

    if (height != null)
      this.height = height;
  }

  write(bw) {
    bw.writeU8(this.type);

    if (this.type === types.SUBMIT_FINALIZE)
      this.writeSubmitFinalize(bw);
    else if (this.type === types.BLOCK_CONFIRM)
      this.writeBlockConfirm(bw);
    else if (this.type === types.P2PNAMESWAP)
      this.writeP2PNameSwap(bw);
    else if (this.type === types.P2PPUBKEY)
      this.writeP2PPubkey(bw);
  }

  /*
  getSize() {
    let size = 0;
    size += 1;

    return size;
  }
  */

  readSubmitFinalize(br) {
    this.data.name = br.readVarString();
  }

  writeSubmitFinalize(bw) {
    bw.writeVarString(this.data.name);
  }

  readBlockConfirm(br) {
    this.data.name = br.readVarString();
  }

  writeBlockConfirm(br) {
    bw.writeVarString(this.data.name);
  }

  readP2PNameSwap(br) {
    this.data.name = br.readVarString();
    this.data.pubkey = br.readBytes(33);
    this.data.signature = br.readBytes(64);
    this.data.value = br.readU64();
    this.data.address = Address.decode(br.readVarBytes());
  }

  writeP2PNameSwap(bw) {
    bw.writeVarString(this.data.name);
    bw.writeBytes(this.data.pubkey);
    bw.writeBytes(this.data.signature);
    bw.writeU64(this.data.value);
    bw.writeVarBytes(this.data.address.encode());
  }

  readP2PPubkey(br) {
    this.data.pubkey = br.readBytes(33);
  }

  writeP2PPubkey(bw) {
    bw.writeBytes(this.data.pubkey);
  }

  fromJSON(json) {
    assert((json.height >>> 0) === json.height);
    assert(typeof json.type === 'string');
    assert(json.data);

    this.height = json.height;
    this.type = types[json.type];
    this.data = json.data;

    return this;
  }

  toJSON(network) {
    const data = {};
    if (this.data.name)
      data.name = this.data.name;
    if (this.data.pubkey)
      data.pubkey = this.data.pubkey.toString('hex');
    if (this.data.signature)
      data.signature = this.data.signature.toString('hex');
    if (typeof this.data.value === 'number')
      data.value = this.data.value;
    if (this.data.address)
      data.address = this.data.address.toString(network);

    return {
      type: typesByVal[this.type],
      height: this.height,
      data: data
    }
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }
}

class JobList extends bio.Struct {
  constructor() {
    super();

    this.jobs = [];
  }

  read(br) {
    const count = br.readVarInt();

    for (let i = 0; i < count; i++) {
      const raw = br.readVarBytes();
      jobs.push(Job.decode(raw));
    }

  }

  write(bw) {
    bw.sizeVarBytes(this.jobs.length);

    for (const job of jobs)
      bw.writeVarBytes(job.encode());
  }

  /*
  getSize() {

  }
  */

  fromOptions(options) {
    assert(Array.isArray(options.jobs));

    for (const job of options.jobs)
      this.jobs.push(Job.fromOptions(job));

    return this;
  }

  fromJSON(json) {
    assert(Array.isArray(options.jobs));

    for (const job of options.jobs)
      this.jobs.push(Job.fromJSON(job));

    return this;
  }

  toJSON() {
    const jobs = [];
    for (const job of this.jobs)
      jobs.push(job.toJSON());

    return jobs;
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }

  static fromJSON(json) {
    return new this().fromJSON(json);
  }
}

exports.Job = Job;
exports.JobList = JobList;
exports.types = types;
exports.typesByVal = typesByVal;
