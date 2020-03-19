/*!
 * seeds.js - seeds for hsd
 * Copyright (c) 2017, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/hsd
 */

'use strict';

exports.get = function get(type) {
  switch (type) {
    case 'main':
      return [];
    case 'testnet':
      return [];
    default:
      return [];
  }
};
