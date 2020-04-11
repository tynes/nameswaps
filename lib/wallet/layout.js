/**
 *
 */

'use strict';

const bdb = require('bdb');

/**
 * SwapWalletDB layout
 *
 * p[addr-hash] -> wallet ids
 * P[wid][addr-hash] -> path data
 * r[wid][index][hash] -> path account index
 */

const swdb = {
  p: bdb.key('p', ['hash']),
  P: bdb.key('P', ['uint32', 'hash']),
  r: bdb.key('r', ['uint32', 'uint32', 'hash']),

  // o: bdb.key('o', [])
};

/**
 * SwapTXDB layout:
 *
 * s[version][scripthash] -> path
 * p[version][scripthash] -> program
 */

const stxdb = {
  prefix: bdb.key('t', ['uint32']),
  s: bdb.key('s', ['hash256']),
  p: bdb.key('p', ['hash256'])
};

module.exports = {
  swdb: swdb,
  stxdb: stxdb
}
