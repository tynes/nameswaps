/**
 *
 */

const assert = require('bsert');
const Chain = require('hsd/lib/blockchain/chain');
const Block = require('hsd/lib/primitives/block');
const Address = require('hsd/lib/primitives/address');
const TX = require('hsd/lib/primitives/tx');
const Input = require('hsd/lib/primitives/input');
const chainCommon = require('hsd/lib/blockchain/common');
const Network = require('hsd/lib/protocol/network');
const Outpoint = require('hsd/lib/primitives/outpoint');
const NameSwaps = require('../lib/core/nameswaps');
const Program = require('../lib/primitives/program');
const SwapProof = require('../lib/primitives/swapproof');
const Pool = require('../lib/net/pool');
const packets = require('../lib/net/packets');
const random = require('bcrypto/lib/random');
const packetTypesByVal = packets.typesByVal;
const common = require('./util/common');

const network = Network.get('regtest');

let one, two;
describe('Pool', function () {
  beforeEach(async () => {
    one = await mockNode({
      port: 1300,
      nodes: ['127.0.0.1:1400'],
      agent: 'one'
    });

    two = await mockNode({
      port: 1400,
      nodes: ['127.0.0.1:1300'],
      agent: 'two'
    });
  });

  afterEach(async () => {
    await one.close();
    await two.close();
  });

  it('should connect', async () => {
    let connections = {
      one: false,
      two: false
    };

    one.pool.once('connection', () => {
      connections.one = true;
    });

    two.pool.once('connection', () => {
      connections.two = true;
    });

    one.pool.once('listening', () => {
      listening.one = true
    });

    two.pool.once('listening', () => {
      listening.two = true;
    });

    const listening = {
      one: false,
      two: false
    };

    await one.open();
    await common.forValue(listening, 'one', true);

    await two.open();
    await common.forValue(listening, 'two', true);

    await one.connect();
    await two.connect();

    assert.equal(connections.one, true);
    assert.equal(connections.two, true);
  });

  it('should send gettip message', async () => {
    await one.open();
    await two.open();
    await one.connect();
    await two.connect();

    const peer = one.pool.peers.get(two.id);
    await one.pool.sendGetTip(peer);
    await common.forValue(one.packetsCount, 'TIP', 1);

    assert.equal(one.packets.TIP.length, 1);
    assert.equal(two.packets.GETTIP.length, 1);

    const [tipPacket] = one.packets.TIP;
    const [getTipPacket] = two.packets.GETTIP;

    assert(tipPacket);
    assert(getTipPacket)

    assert.bufferEqual(tipPacket.hash, two.nameswaps.tip.hash);
    assert.equal(tipPacket.height, two.nameswaps.tip.height);
  });

  it('should send updated tip message', async () => {
    await one.open();
    await two.open();
    await one.connect();
    await two.connect();

    const block = new Block();
    block.prevBlock = network.genesis.hash;
    block.time = network.genesis.time + 1;
    block.bits = 545259519;
    block.txs = [
      new TX({
        locktime: 1,
        inputs: [new Input()]
      })
    ];

    await one.chain.add(block, chainCommon.flags.VERIFY_NONE);
    assert.deepEqual(one.chain.tip, one.nameswaps.tip);

    const peer = two.pool.peers.get(one.id);
    await two.pool.sendGetTip(peer);

    let tipPacket;
    await common.forCallback(() => {
      for (const packet of two.packets.TIP) {
        if (packet.hash.equals(block.hash())) {
          tipPacket = packet;
          return true;
        }
      }
      return false;
    });

    assert.bufferEqual(tipPacket.hash, one.nameswaps.tip.hash);
    assert.equal(tipPacket.height, one.nameswaps.tip.height);

    assert.bufferEqual(peer.bestHash, tipPacket.hash);
    assert.equal(peer.height, tipPacket.height);
  });

  it('should send getprogram and receive program (not found)', async () => {
    await one.open();
    await two.open();
    await one.connect();
    await two.connect();

    const outpoint = {
      hash: random.randomBytes(32),
      index: 0
    };

    const peer = one.pool.peers.get(two.id);
    await one.pool.sendGetProgram(peer, outpoint.hash, outpoint.index);

    await common.forValue(one.packetsCount, 'PROGRAM', 1);
    await common.forValue(two.packetsCount, 'GETPROGRAM', 1);

    const [programPacket] = one.packets.PROGRAM;
    const [getProgramPacket] = two.packets.GETPROGRAM;

    assert.equal(programPacket.program.isNull(), true);
    assert.bufferEqual(getProgramPacket.hash, outpoint.hash);
    assert.equal(getProgramPacket.index, outpoint.index);
  });

  it('should send getprogram and receive program (found)', async () => {
    await one.open();
    await two.open();
    await one.connect();
    await two.connect();

    const program = Program.fromOptions({
      type: Program.types.PUBKEY,
      data: random.randomBytes(33),
      outpoint: new Outpoint(random.randomBytes(32), 0)
    });

    assert(await two.nameswaps.putProgram(program));

    const peer = one.pool.peers.get(two.id);
    await one.pool.sendGetProgram(peer, program.outpoint.hash, program.outpoint.index);

    await common.forValue(one.packetsCount, 'PROGRAM', 1);
    await common.forValue(two.packetsCount, 'GETPROGRAM', 1);

    const [programPacket] = one.packets.PROGRAM;
    const [getProgramPacket] = two.packets.GETPROGRAM;

    assert.equal(programPacket.program.isNull(), false);
    assert.bufferEqual(getProgramPacket.hash, program.outpoint.hash);
    assert.equal(getProgramPacket.index, program.outpoint.index);
  });

  it('should send getswapproof and receive swapproof (notfound)', async () => {
    await one.open();
    await two.open();
    await one.connect();
    await two.connect();

    const peer = one.pool.peers.get(two.id);
    await one.pool.sendGetSwapProof(peer, 'foobar');

    await common.forValue(one.packetsCount, 'SWAPPROOF', 1);
    await common.forValue(two.packetsCount, 'GETSWAPPROOF', 1);

    const [swapProofPacket] = one.packets.SWAPPROOF;
    const [getSwapProofPacket] = two.packets.GETSWAPPROOF;

    assert.equal(swapProofPacket.proof.isNull(), true);
    assert.equal(getSwapProofPacket.name, 'foobar');
  });

  it('should send getswapproof and receive swapproof (found)', async () => {
    await one.open();
    await two.open();
    await one.connect();
    await two.connect();

    const program = Program.fromOptions({
      type: Program.types.PUBKEY,
      data: random.randomBytes(33),
      outpoint: new Outpoint(random.randomBytes(32), 0)
    });

    const proof = SwapProof.fromOptions({
      version: 1,
      name: 'testing',
      program: program,
      signature: random.randomBytes(64),
      address: new Address(),
      value: 1000
    });

    assert(await two.nameswaps.putSwapProof(proof));

    const peer = one.pool.peers.get(two.id);
    await one.pool.sendGetSwapProof(peer, proof.name);

    await common.forValue(one.packetsCount, 'SWAPPROOF', 1);
    await common.forValue(two.packetsCount, 'GETSWAPPROOF', 1);

    const [swapProofPacket] = one.packets.SWAPPROOF;
    const [getSwapProofPacket] = two.packets.GETSWAPPROOF;

    console.log(swapProofPacket);
    console.log(getSwapProofPacket);

    assert.equal(swapProofPacket.proof.isNull(), false);
  });

  it('should do stuff', async () => {
    await one.open();
    await two.open();
    await one.connect();
    await two.connect();

    // here

  });
});

function mockNode(options) {
  const chain = new Chain({
    network: network,
    memory: true
  });

  const nameswaps = new NameSwaps({
    network: network,
    chain: chain,
    memory: true
  });

  const pool = new Pool({
    nameswaps: nameswaps,
    chain: chain,
    listen: true,
    port: options.port,
    nodes: options.nodes,
    agent: options.agent
  });

  const packets = {};
  const packetsCount = {};

  pool.on('packet', (packet) => {
    if (!packets[packetTypesByVal[packet.type]])
      packets[packetTypesByVal[packet.type]] = [];
    if (!packetsCount[packetTypesByVal[packet.type]])
      packetsCount[packetTypesByVal[packet.type]] = 0;

    packets[packetTypesByVal[packet.type]].push(packet);
    packetsCount[packetTypesByVal[packet.type]]++;
  });

  async function open() {
    await chain.open();
    await nameswaps.open();
    await pool.open();
    await pool.listen();
  }

  async function connect() {
    await pool.connect();
  }

  async function close() {
    await nameswaps.close();
    await chain.close();
    await pool.close();
  }

  return {
    chain: chain,
    nameswaps: nameswaps,
    pool: pool,
    close: close,
    options: options,
    open: open,
    connect: connect,
    id: `127.0.0.1:${options.port}`,
    packets: packets,
    packetsCount: packetsCount
  }
}

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}
