/**
 *
 */

'use strict';

const assert = require('bsert');
const {Job, JobList, types, typesByVal} = require('../lib/core/jobs');
const Address = require('hsd/lib/primitives/address');
const Network = require('hsd/lib/protocol/network');
const network = Network.get('testnet');

describe('Job', function () {
  this.skip();

  describe('SUBMIT_FINALIZE', () => {
    it('should instantiate from options', () => {
      const options = {
        type: types.SUBMIT_FINALIZE,
        height: 1,
        data: {
          name: 'foo'
        }
      }

      const job = Job.fromOptions(options);

      assert.strictEqual(job.type, options.type);
      assert.strictEqual(job.height, options.height);
      assert.deepEqual(job.data, options.data);
    });

    it('should serialize/deserialize', () => {;
      const options = {
        type: types.SUBMIT_FINALIZE,
        height: 10,
        data: {
          name: 'bar'
        }
      }

      const job = Job.fromOptions(options);
      const raw = job.encode();
      const got = Job.decode(raw, options.height);

      assert.bufferEqual(raw, got.encode());
      assert.strictEqual(job.type, got.type);
      assert.strictEqual(job.height, got.height);
      assert.strictEqual(job.data.name, got.data.name);
    });

    it('should to/from json', () => {
      const json = {
        type: 'SUBMIT_FINALIZE',
        height: 10,
        data: {
          name: 'bar'
        }
      }

      const job = Job.fromJSON(json);
      assert.deepEqual(json, job.toJSON());
    });
  });

  describe('P2PPUBKEY', function() {
    it('should instantiate from options', () => {
      const options = {
        type: types.P2PPUBKEY,
        height: 45,
        data: {
          pubkey: Buffer.alloc(33)
        }
      }

      const job = Job.fromOptions(options);

      assert.strictEqual(job.type, options.type);
      assert.strictEqual(job.height, options.height);
      assert.deepEqual(job.data, options.data);
    });

    it('should serialize/deserialize', () => {
      const options = {
        type: types.P2PPUBKEY,
        height: 45,
        data: {
          pubkey: Buffer.alloc(33)
        }
      }

      const job = Job.fromOptions(options);
      const raw = job.encode();
      const got = Job.decode(raw, options.height);

      assert.bufferEqual(raw, got.encode());
      assert.strictEqual(job.type, got.type);
      assert.strictEqual(job.height, got.height);
      assert.bufferEqual(job.data.pubkey, got.data.pubkey);
    });

    it('should to/from json', () => {
      const json = {
        type: 'P2PPUBKEY',
        height: 101,
        data: {
          pubkey: Buffer.alloc(33).toString('hex')
        }
      }

      const job = Job.fromJSON(json);
      assert.deepEqual(json, job.toJSON());
    });
  });

  let addr = 'ts1qhl0zw3mtffpk566q7dglgkn9y67myf36fnqasr';

  describe('P2PNAMESWAP', function() {
    it('should instantiate from options', () => {
      const options = {
        type: types.P2PNAMESWAP,
        height: 10002,
        data: {
          name: 'foo',
          pubkey: Buffer.alloc(33),
          signature: Buffer.alloc(64),
          value: 100,
          address: Address.fromString(addr)
        }
      }

      const job = Job.fromOptions(options);

      assert.strictEqual(job.type, options.type);
      assert.strictEqual(job.height, options.height);
      assert.deepEqual(job.data, options.data);
    });

    it('should serialize/deserialize', () => {
      const options = {
        type: types.P2PNAMESWAP,
        height: 10002,
        data: {
          name: 'foo',
          pubkey: Buffer.alloc(33),
          signature: Buffer.alloc(64, 0xff),
          value: 1000,
          address: Address.fromString(addr)
        }
      }

      const job = Job.fromOptions(options);
      const raw = job.encode();
      const got = Job.decode(raw, options.height);

      assert.bufferEqual(raw, got.encode());
      assert.strictEqual(job.type, got.type);
      assert.strictEqual(job.height, got.height);
      assert.deepEqual(job.data, got.data);
    });

    it('should to/from json', () => {
      const json = {
        type: 'P2PNAMESWAP',
        height: 1010,
        data: {
          name: 'foo',
          pubkey: Buffer.alloc(33).toString('hex'),
          signature: Buffer.alloc(64, 0xff).toString('hex'),
          value: 1000,
          address: addr
        }
      }

      const job = Job.fromJSON(json);
      assert.deepEqual(json, job.toJSON(network));
    });
  });
});

describe('JobList', function() {
  let addr = 'ts1qhl0zw3mtffpk566q7dglgkn9y67myf36fnqasr';

  it('Should create job list from options', () => {
    const jobs = [
      {
        type: types.SUBMIT_FINALIZE,
        height: 1,
        data: {
          name: 'foo'
        }
      },
      {
        type: types.P2PPUBKEY,
        height: 45,
        data: {
          pubkey: Buffer.alloc(33)
        }
      },
      {
        type: types.P2PNAMESWAP,
        height: 13034,
        name: 'foo',
        pubkey: Buffer.alloc(33),
        signature: Buffer.alloc(64, 0xff),
        value: 1000,
        address: Address.fromString(addr)
      }
    ];

    const joblist = JobList.fromOptions({jobs});

    assert.equal(joblist.jobs.length, jobs.length);
    for (let i = 0; i < jobs.length; i++) {
      const job = Job.fromOptions(jobs[i]);
      assert.deepEqual(joblist.jobs[i], job);
    }
  });
});
