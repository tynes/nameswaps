#!/usr/bin/env node

'use strict';

process.title = 'hsd-nameswaps';

if (process.argv.indexOf('--help') !== -1
    || process.argv.indexOf('-h') !== -1) {
  console.error('See the hsd docs at:');
  console.error('https://handshake-org.github.io');
  process.exit(1);
  throw new Error('Could not exit.');
}

if (process.argv.indexOf('--version') !== -1
    || process.argv.indexOf('-v') !== -1) {
  const pkg = require('../package.json');
  console.log(pkg.version);
  process.exit(0);
  throw new Error('Could not exit.');
}

const blake2b = require('bcrypto/lib/blake2b');
const secp256k1 = require('bcrypto/lib/secp256k1');

if (blake2b.native !== 2) {
  console.error('Bindings for bcrypto were not built.');
  console.error('Please build them before continuing.');
  process.exit(1);
  return;
}

if (secp256k1.native !== 2) {
  console.error('Bindings for libsecp256k1 were not built.');
  console.error('Please build them before continuing.');
  process.exit(1);
  return;
}

const FullNode = require('../lib/node/fullnode');

const node = new FullNode({
  config: true,
  argv: true,
  env: true,
  logFile: true,
  logConsole: true,
  logLevel: 'debug',
  memory: false,
  workers: true,
  listen: false,
  network: 'main',
  loader: require
});

const plugin = require('./lib/plugin');

// Temporary hack
if (!node.config.bool('no-wallet') && !node.has('walletdb')) {
  const plugin = require('../lib/wallet/plugin');
  node.use(plugin);
}

process.on('unhandledRejection', (err, promise) => {
  throw err;
});

(async () => {
  await node.ensure();
  await node.open();
  await node.connect();
  node.startSync();
})().catch((err) => {
  console.error(err.stack);
  process.exit(1);
});
