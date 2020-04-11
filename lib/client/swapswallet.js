
const {WalletClient} = require('hs-client');
const EventEmitter = require('events');

class SwapsWalletClient extends WalletClient {
  constructor(options) {
    super(options);
  }

  wallet(id, token) {
    const wallet = super.wallet(id, token);
    return SwapsWallet(wallet);
  }

  createSwapAddress(id, account) {
    return this.post(`/nameswaps/wallet/${id}/address`, {account});
  }

  getSwapCoins() {
    return this.get(`/nameswaps/wallet/${id}/coin`, {account});
  }

  getSwapKey(id, address) {
    return this.get(`/nameswaps/wallet/${id}/key/${address}`);
  }
}

function SwapsWallet(Wallet) {
  Wallet.createSwapAddress = function(account) {
    return this.client.createSwapAddress(this.id, account);
  };

  Wallet.getSwapCoins = function(account) {
    return this.client.getSwapCoins(account);
  };

  Wallet.getSwapKey = function(address) {
    return this.client.getSwapKey(address);
  };

  return Wallet;
}

module.exports = SwapsWalletClient;
