/**
 * layout.js - Database layout for NameSwaps
 */

'use strict';

const bdb = require('bdb');

/**
 * Database layout:
 *  V -> db version
 *  R -> tip hash
 *  s[name] -> swap proof
 *  p[hash][index] -> program
 *  S[block hash][tx hash][index] -> dummy (get outpoints by block hash)
 *  P[block hash][tx hash][index] -> dummy (get outpoints by block hash)
 *  j[height] -> job list
 *  n[name] -> job list
 *
 *
 *  SwapProofs are indexed by name
 *    - Get all available names
 *  Programs are indexed by outpoint
 *    - Get coin by outpoint to get coin
 *  S and P are useful for p2p syncing
 */

const layout = {
  V: bdb.key('V'),
  R: bdb.key('R'),
  s: bdb.key('s', ['ascii']),
  p: bdb.key('p', ['hash256', 'uint32']),
  S: bdb.key('S', ['hash256', 'hash256', 'uint32']),
  P: bdb.key('P', ['hash256', 'hash256', 'uint32']),
  j: bdb.key('j', ['uint32']),
  n: bdb.key('n', ['ascii'])
};

module.exports = layout;
