/**
 *
 */

function SwapsNetwork(network) {
  network.swapsPort = network.port + 10;
  network.swapsRpcPort = network.port + 11;
  network.swapsWalletRpcPort = network.port + 12;

  network.swapsMagic = network.magic + 100;

  return network;
}

module.exports = SwapsNetwork;
