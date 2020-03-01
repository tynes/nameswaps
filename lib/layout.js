/**
 * layout.js - Database layout for NameSwaps
 */

'use strict';

const bdb = require('bdb');

/**
 * Database layout:
 *  V -> db version
 *  R -> tip hash
 *  a[version][data] -> preimage
 *  b[hash][prevout] -> dummy (get prevouts by block hash)
 *  j[height] -> job list
 *  n[name] -> job list
 *
 *  The preimages are indexed by the address
 *  version and data. The b index is useful for
 *  getting all prevouts with a known addrwitness
 *  by blockhash.
 */

const layout = {
  V: bdb.key('V'),
  R: bdb.key('R'),
  a: bdb.key('a', ['uint8', 'buffer']),
  b: bdb.key('b', ['hash256', 'buffer']),
  j: bdb.key('j', ['uint32']),
  n: bdb.key('n', ['buffer'])
};

module.exports = layout;
