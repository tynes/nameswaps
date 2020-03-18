
/**
 * p2p magic numbers
 */

// TODO: make a network object
exports.magic = {
  main: Buffer.from('70dead40', 'hex'),
  testnet: Buffer.from('60dead40', 'hex'),
  regtest: Buffer.from('50dead40', 'hex'),
  simnet: Buffer.from('40dead40', 'hex'),
}

// TODO: set this correctly
exports.MAX_MESSAGE = 1024;
