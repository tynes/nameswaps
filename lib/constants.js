
/**
 * p2p magic numbers
 */

exports.magic = {
  main: Buffer.from(0x70dead40, 'hex');
  testnet: Buffer.from(0x60dead40, 'hex');
  regtest: Buffer.from(0x50dead40, 'hex');
  simnet: Buffer.from(0x40dead40, 'hex');
}

// TODO: set this correctly
exports.MAX_MESSAGE = 1024;
