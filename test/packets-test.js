/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';

const assert = require('bsert');
const {nonce} = require('../lib/net/common');
const Program = require('../lib/primitives/program');
const SwapProof = require('../lib/primitives/swapproof');
const Framer = require('../lib/net/framer');
const packets = require('../lib/net/packets');
const NetAddress = require('../lib/net/netaddress');
const InvItem = require('../lib/net/invitem');
const SwapsNetwork = require('../lib/core/swapsnetwork');
const Network = require('hsd/lib/protocol/network');

const networks = {
  main: SwapsNetwork(Network.get('main')),
  testnet: SwapsNetwork(Network.get('testnet')),
  regtest: SwapsNetwork(Network.get('regtest')),
  simnet: SwapsNetwork(Network.get('simnet'))
};

describe('Net', function() {
  describe('Packets', function() {
    it('should encode/decode version packets', () => {
      const check = (pkt) => {
        assert.equal(pkt.type, packets.types.VERSION);
        assert.equal(pkt.version, 70012);
        assert.equal(pkt.services, 10);
        assert.equal(pkt.time, 1558405603);
        assert.equal(pkt.remote.host, '127.0.0.1');
        assert.equal(pkt.remote.port, 8334);
        assert.bufferEqual(pkt.nonce, Buffer.alloc(8, 0x00));
        assert.equal(pkt.agent, 'hsd');
        assert.equal(pkt.height, 500000);
        assert.equal(pkt.noRelay, true);
      };

      let pkt = new packets.VersionPacket({
        version: 70012,
        services: 10,
        time: 1558405603,
        remote: {
          host: '127.0.0.1',
          port: 8334
        },
        local: {
          host: '127.0.0.1',
          port: 8335
        },
        nonce: Buffer.alloc(8, 0x00),
        agent: 'hsd',
        height: 500000,
        noRelay: true
      });
      check(pkt);

      pkt = packets.VersionPacket.decode(pkt.encode());
      check(pkt);
    });

    it('should encode/decode verack packets', () => {
      const check = (pkt) => {
        assert.equal(pkt.type, packets.types.VERACK);
      };

      let pkt = new packets.VerackPacket();
      check(pkt);

      pkt = packets.VerackPacket.decode(pkt.encode());
      check(pkt);
    });

    it('should encode/decode ping packets', () => {
      const check = (pkt) => {
        assert.equal(pkt.type, packets.types.PING);
        assert.bufferEqual(pkt.nonce, Buffer.alloc(8, 0x01));
      };

      let pkt = new packets.PingPacket(Buffer.alloc(8, 0x01));
      check(pkt);

      pkt = packets.PingPacket.decode(pkt.encode());
      check(pkt);
    });

    it('should encode/decode pong packets', () => {
      const check = (pkt) => {
        assert.equal(pkt.type, packets.types.PONG);
        assert.bufferEqual(pkt.nonce, Buffer.alloc(8, 0x01));
      };

      let pkt = new packets.PongPacket(Buffer.alloc(8, 0x01));
      check(pkt);

      pkt = packets.PongPacket.decode(pkt.encode());
      check(pkt);
    });

    it('should encode/decode getaddr packets', () => {
      const check = (pkt) => {
        assert.equal(pkt.type, packets.types.GETADDR);
      };

      let pkt = new packets.GetAddrPacket();
      check(pkt);

      pkt = packets.GetAddrPacket.decode(pkt.encode());
      check(pkt);
    });

    it('should encode/decode addr packets', () => {
      const check = (pkt) => {
        assert.equal(pkt.type, packets.types.ADDR);

        let addr = pkt.items[0];
        assert.equal(addr.host, '127.0.0.2');
        assert.equal(addr.port, 8334);
        assert.equal(addr.services, 101);
        assert.equal(addr.time, 1558405603);

        addr = pkt.items[1];
        assert.equal(addr.host, '127.0.0.3');
        assert.equal(addr.port, 8333);
        assert.equal(addr.services, 102);
        assert.equal(addr.time, 1558405602);
      };

      const items = [
        new NetAddress({
          host: '127.0.0.2',
          port: 8334,
          services: 101,
          time: 1558405603
        }),
        new NetAddress({
          host: '127.0.0.3',
          port: 8333,
          services: 102,
          time: 1558405602
        })
      ];

      let pkt = new packets.AddrPacket(items);
      check(pkt);

      pkt = packets.AddrPacket.decode(pkt.encode());
      check(pkt);
    });

    it('should encode/decode inv packets', () => {
      const check = (pkt, many) => {
        assert.equal(pkt.type, packets.types.INV);

        let item = pkt.items[0];
        assert.equal(item.type, 1);
        assert.bufferEqual(item.data, Buffer.alloc(32, 0x01));

        item = pkt.items[1];
        assert.equal(item.type, 1);
        assert.bufferEqual(item.data, Buffer.alloc(32, 0x02));

        if (many) {
          for (let i = 2; i < 254; i++) {
            item = pkt.items[i];
            assert.equal(item.type, 1);
            assert.bufferEqual(item.data, Buffer.alloc(32, 0x03));
          }
        }
      };

      const items = [
        new InvItem(InvItem.types.PROGRAM, Buffer.alloc(32, 0x01)),
        new InvItem(InvItem.types.PROGRAM, Buffer.alloc(32, 0x02))
      ];

      let pkt = new packets.InvPacket(items);
      check(pkt, false);

      pkt = packets.InvPacket.decode(pkt.encode());
      check(pkt, false);

      while (items.length < 254)
        items.push(new InvItem(InvItem.types.PROGRAM, Buffer.alloc(32, 0x03)));

      pkt = new packets.InvPacket(items);
      check(pkt, true);

      pkt = packets.InvPacket.decode(pkt.encode());
      check(pkt, true);
    });

    it('should encode/decode getdata packets', () => {
      const check = (pkt) => {
        assert.equal(pkt.type, packets.types.GETDATA);

        let item = pkt.items[0];
        assert.equal(item.type, 1);
        assert.bufferEqual(item.data, Buffer.alloc(32, 0x01));

        item = pkt.items[1];
        assert.equal(item.type, 1);
        assert.bufferEqual(item.data, Buffer.alloc(32, 0x02));
      };

      const items = [
        new InvItem(InvItem.types.PROGRAM, Buffer.alloc(32, 0x01)),
        new InvItem(InvItem.types.PROGRAM, Buffer.alloc(32, 0x02))
      ];

      let pkt = new packets.GetDataPacket(items);
      check(pkt);

      pkt = packets.GetDataPacket.decode(pkt.encode());
      check(pkt);
    });

    it('should encode/decode notfound packets', () => {
      const check = (pkt) => {
        assert.equal(pkt.type, packets.types.NOTFOUND);

        let item = pkt.items[0];
        assert.equal(item.type, 1);
        assert.bufferEqual(item.data, Buffer.alloc(32, 0x01));

        item = pkt.items[1];
        assert.equal(item.type, 1);
        assert.bufferEqual(item.data, Buffer.alloc(32, 0x02));
      };

      const items = [
        new InvItem(InvItem.types.PROGRAM, Buffer.alloc(32, 0x01)),
        new InvItem(InvItem.types.PROGRAM, Buffer.alloc(32, 0x02))
      ];

      let pkt = new packets.NotFoundPacket(items);
      check(pkt);

      pkt = packets.NotFoundPacket.decode(pkt.encode());
      check(pkt);
    });

    it('should encode/decode gettip packets', () => {
      const check = (pkt) => {
        assert.equal(pkt.type, packets.types.GETTIP);
      };

      let pkt = new packets.GetTipPacket();

      check(pkt);

      pkt = packets.GetTipPacket.decode(pkt.encode());
      check(pkt);
    });

    it('should encode/decode tip packets', () => {
      const check = (pkt) => {
        assert.equal(pkt.type, packets.types.TIP);
        assert.bufferEqual(pkt.hash, Buffer.alloc(32));
        assert.equal(pkt.height, 10);
      };

      let pkt = new packets.TipPacket(Buffer.alloc(32), 10);

      pkt = packets.TipPacket.decode(pkt.encode());
      check(pkt)
    });

    it('should encode/decode getprogram packets', () => {
      const check = (pkt) => {
        assert.equal(pkt.type, packets.types.GETPROGRAM);
        assert.bufferEqual(pkt.hash, Buffer.alloc(32, 0x11));
        assert.equal(pkt.index, 10);
      }

      let pkt = new packets.GetProgramPacket(Buffer.alloc(32, 0x11), 10);
      check(pkt);

      pkt = packets.GetProgramPacket.decode(pkt.encode());
      check(pkt);
    });

    it('should encode/decode program packets', () => {
      const check = (pkt) => {
        assert.equal(pkt.type, packets.types.PROGRAM);
        assert.deepEqual(pkt.program, new Program());
        assert.bufferEqual(pkt.hash, Buffer.alloc(32, 0x22));
        assert.equal(pkt.index, 1);
      }

      const program = new Program();
      const hash = Buffer.alloc(32, 0x22);
      const index = 1;

      let pkt = new packets.ProgramPacket(program, hash, index);

      pkt = packets.ProgramPacket.decode(pkt.encode());
      check(pkt);
    });

    it('should encode/decode getswapproof packets', () => {
      const check = (pkt) => {
        assert.equal(pkt.type, packets.types.GETSWAPPROOF);
        assert.equal(pkt.name, 'foobar');
      };

      let pkt = new packets.GetSwapProofPacket('foobar');
      check(pkt);

      pkt = packets.GetSwapProofPacket.decode(pkt.encode());
      check(pkt);
    });

    it('should encode/decode swapproof packets', () => {
      const check = (pkt) => {
        assert.equal(pkt.type, packets.types.SWAPPROOF);
        assert.deepEqual(pkt.proof, new SwapProof());
      }

      let pkt = new packets.SwapProofPacket(new SwapProof())
      check(pkt);

      pkt = packets.SwapProofPacket.decode(pkt.encode());
      check(pkt);
    });

    it('should encode/decode getdatasync packets', () => {
      const locator = [
        Buffer.alloc(32, 0x00),
        Buffer.alloc(32, 0x11),
        Buffer.alloc(32, 0x22),
      ];
      const stop = Buffer.alloc(32, 0xff);

      const flags = 0
        | packets.GetDataSyncPacket.flags.PROGRAM
        | packets.GetDataSyncPacket.flags.SWAPPROOF;

      const check = (pkt) => {
        assert.equal(pkt.type, packets.types.GETDATASYNC);
        assert.deepEqual(pkt.locator, locator);
        assert.bufferEqual(pkt.stop, stop);
        assert.strictEqual(pkt.flags, flags);
      };

      let pkt = new packets.GetDataSyncPacket(locator, stop, flags);
      check(pkt);

      pkt = packets.GetDataSyncPacket.decode(pkt.encode());
      check(pkt);
    });

    it('should encode/decode datasync packets', () => {
      const items = [
        new packets.SwapProofPacket(new SwapProof()),
        new packets.ProgramPacket(new Program()),
        new packets.ProgramPacket(new Program()),
        new packets.SwapProofPacket(new SwapProof())
      ];

      const notFound = [
        [Buffer.alloc(32), Buffer.alloc(32)],
        [Buffer.alloc(32), Buffer.alloc(32)]
      ];

      const check = (pkt) => {
        assert.equal(pkt.type, packets.types.DATASYNC);
        assert.equal(pkt.items.length, items.length);
        assert.deepEqual(pkt.items, items);
        assert.equal(pkt.notFound.length, notFound.length);
        assert.deepEqual(pkt.notFound, notFound);
      };

      let pkt = new packets.DataSyncPacket(items, notFound);
      check(pkt);

      pkt = packets.DataSyncPacket.decode(pkt.encode());
      check(pkt);
    });

    it('should encode/decode reject packets', () => {
      const check = (pkt) => {
        assert.equal(pkt.type, packets.types.REJECT);
        assert.equal(pkt.message, packets.types.SWAPPROOF);
        assert.equal(pkt.reason, 'swapproof');
        assert.equal(packets.typesByVal[pkt.message], 'SWAPPROOF');
        assert.equal(pkt.getCode(), 'invalid');
        assert.bufferEqual(pkt.hash, Buffer.alloc(32, 0x01));
      };

      let pkt = new packets.RejectPacket({
        message: packets.types.SWAPPROOF,
        code: packets.RejectPacket.codes.INVALID,
        reason: 'swapproof',
        hash: Buffer.alloc(32, 0x01)
      });

      check(pkt);

      pkt = packets.RejectPacket.decode(pkt.encode());
      check(pkt);

      pkt = packets.RejectPacket.fromReason(
        'invalid',
        'swapproof',
        packets.types.SWAPPROOF,
        Buffer.alloc(32, 0x01)
      );

      check(pkt);

      pkt = packets.RejectPacket.decode(pkt.encode());
      check(pkt);
    });
  });


  describe('Framer', function() {
    this.skip();

    it('will construct with network (primary)', () => {
      //const framer = new Framer();
      assert.strictEqual(framer.network, Network.get('main'));
    });

    it('will construct with network (custom)', () => {
      //const framer = new Framer('regtest');
      assert.strictEqual(framer.network, Network.get('regtest'));
    });

    it('throw with long command', () => {
      //const framer = new Framer('regtest');
      let err = null;

      // Packet types are defined by a uint8.
      // Pass a number that is too large and
      // assert there is an error.
      try {
        framer.packet(256, Buffer.alloc(2, 0x00));
      } catch (e) {
        err = e;
      }
      assert(err);
      assert(err.type, 'AssertionError');
    });

    it('will frame payload with header', () => {
      //const framer = new Framer('regtest');
      const network = Network.get('regtest');
      const buf = Buffer.alloc(2, 0x01);

      const pkt = framer.packet(packets.types.PING, buf);

      const magic = pkt.slice(0, 4);
      assert.equal(magic.readUInt32LE(), network.magic);

      const cmd = pkt.slice(4, 5);
      assert.equal(cmd.readUInt8(), packets.types.PING);

      const len = pkt.slice(5, 9).readUInt32LE();

      const cmdbuf = pkt.slice(9, 9 + len);
      assert.bufferEqual(cmdbuf, buf);
    });
  });

  describe('Common', function() {
    it('will give nonce', async () => {
      const n = nonce();
      assert(Buffer.isBuffer(n));
      assert.equal(n.length, 8);
    });
  });

});
