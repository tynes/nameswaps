/**
 *
 */

function SwapsNetwork(network) {
  network.swapsPort = network.port + 10;
  network.swapsRpcPort = network.port + 11;

  return network;
}

module.exports = SwapsNetwork;
