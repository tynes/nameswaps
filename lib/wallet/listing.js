
// tx is the TRANSFER transaction
// pubkey is used in the nameswap template
// address is owned
// signature commits to address and value
class Listing {
  constructor(options) {
    this.name = null;
    this.tx = null;
    this.pubkey = null;
    this.address = null;
    this.signature = null;

    if (options)
      this.fromOptions(options);
  }

  validate() {
    if (!this.tx)
      return false;

    if (!this.pubkey)
      return false;

    if (!this.address)
      return false;

    if (!this.signature)
      return false;

    return true;
  }

  fromOptions(options) {
    if (options.name != null) {
      assert(typeof options.name === 'string');
      this.name = options.name;
    }

    if (options.tx != null) {
      this.tx = options.tx;
    }

    if (options.pubkey != null) {
      this.pubkey = options.pubkey;
    }

    if (options.address != null) {
      this.address = options.address;
    }

    if (options.signature != null) {
      this.signature = options.signature;
    }

    return this;
  }

  static fromOptions(options) {
    return new this().fromOptions(options);
  }
}

module.exports = Listing;
