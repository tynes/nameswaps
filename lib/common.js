/**
 *
 */

const pkg = require('./pkg');
const random = require('bcrypto/lib/random');

/**
 * Default protocol version.
 * @const {Number}
 * @default
 */

exports.PROTOCOL_VERSION = 1;

/**
 * Minimum protocol version we're willing to talk to.
 * @const {Number}
 * @default
 */

exports.MIN_VERSION = 1;

/**
 * Service bits.
 * @enum {Number}
 * @default
 */

exports.services = {};

/**
 * Our node's services (we support everything).
 * @const {Number}
 * @default
 */

exports.LOCAL_SERVICES = 0;

/**
 * Required services (network).
 * @const {Number}
 * @default
 */

exports.REQUIRED_SERVICES = 0;

/**
 *
 */

exports.USER_AGENT = `/${pkg.name}:${pkg.version}/`;

/**
 * Max message size (~8mb)
 * @const {Number}
 * @default
 */

exports.MAX_MESSAGE = 8 * 1000 * 1000;

/**
 * Amount of time to ban misbheaving peers.
 * @const {Number}
 * @default
 */

exports.BAN_TIME = 24 * 60 * 60;

/**
 * Ban score threshold before ban is placed in effect.
 * @const {Number}
 * @default
 */

exports.BAN_SCORE = 100;

/**
 * Create a nonce.
 * @returns {Buffer}
 */

exports.nonce = function nonce() {
  return random.randomBytes(8);
};

/**
 * A compressed pubkey of all zeroes.
 * @const {Buffer}
 * @default
 */

exports.ZERO_KEY = Buffer.alloc(33, 0x00);

/**
 * A 64 byte signature of all zeroes.
 * @const {Buffer}
 * @default
 */

exports.ZERO_SIG = Buffer.alloc(64, 0x00);

/**
 * 8 zero bytes.
 * @const {Buffer}
 * @default
 */

exports.ZERO_NONCE = Buffer.alloc(8, 0x00);

/**
 * Maximum inv/getdata size.
 * @const {Number}
 * @default
 */

exports.MAX_INV = 50000;

/**
 * Maximum number of requests.
 * @const {Number}
 * @default
 */

exports.MAX_REQUEST = 5000;
