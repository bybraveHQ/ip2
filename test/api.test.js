'use strict';

// Ported from the original node-ip mocha suite (test/api-test.js).
// Cases whose behaviour intentionally changed in the fork live in
// security.test.js (strict parsing, classification, loopback).

const assert = require('node:assert');
const { describe, it } = require('node:test');
const net = require('node:net');
const os = require('node:os');
const { Buffer } = require('node:buffer');
const ip = require('..');

describe('toBuffer()/toString() methods', () => {
  it('should convert to buffer IPv4 address', () => {
    const buf = ip.toBuffer('127.0.0.1');
    assert.equal(buf.toString('hex'), '7f000001');
    assert.equal(ip.toString(buf), '127.0.0.1');
  });

  it('should convert to buffer IPv4 address in-place', () => {
    const buf = Buffer.alloc(128);
    const offset = 64;
    ip.toBuffer('127.0.0.1', buf, offset);
    assert.equal(buf.toString('hex', offset, offset + 4), '7f000001');
    assert.equal(ip.toString(buf, offset, 4), '127.0.0.1');
  });

  it('should convert to buffer IPv6 address', () => {
    const buf = ip.toBuffer('::1');
    assert(/(00){15,15}01/.test(buf.toString('hex')));
    assert.equal(ip.toString(buf), '::1');
    assert.equal(ip.toString(ip.toBuffer('1::')), '1::');
    assert.equal(ip.toString(ip.toBuffer('abcd::dcba')), 'abcd::dcba');
  });

  it('should convert to buffer IPv6 address in-place', () => {
    const buf = Buffer.alloc(128);
    const offset = 64;
    ip.toBuffer('::1', buf, offset);
    assert(/(00){15,15}01/.test(buf.toString('hex', offset, offset + 16)));
    assert.equal(ip.toString(buf, offset, 16), '::1');
    assert.equal(ip.toString(ip.toBuffer('1::', buf, offset), offset, 16), '1::');
    assert.equal(
      ip.toString(ip.toBuffer('abcd::dcba', buf, offset), offset, 16),
      'abcd::dcba',
    );
  });

  it('should convert to buffer IPv6 mapped IPv4 address', () => {
    let buf = ip.toBuffer('::ffff:127.0.0.1');
    assert.equal(buf.toString('hex'), '00000000000000000000ffff7f000001');
    assert.equal(ip.toString(buf), '::ffff:7f00:1');

    buf = ip.toBuffer('ffff::127.0.0.1');
    assert.equal(buf.toString('hex'), 'ffff000000000000000000007f000001');
    assert.equal(ip.toString(buf), 'ffff::7f00:1');

    buf = ip.toBuffer('0:0:0:0:0:ffff:127.0.0.1');
    assert.equal(buf.toString('hex'), '00000000000000000000ffff7f000001');
    assert.equal(ip.toString(buf), '::ffff:7f00:1');
  });

  it('should throw on invalid input', () => {
    assert.throws(() => ip.toBuffer('hello'), /Invalid ip address/);
    assert.throws(() => ip.toBuffer('256.0.0.1'), /Invalid ip address/);
    assert.throws(() => ip.toBuffer('1:2:3:4:5:6:7:8:9'), /Invalid ip address/);
  });
});

describe('fromPrefixLen() method', () => {
  it('should create IPv4 mask', () => {
    assert.equal(ip.fromPrefixLen(24), '255.255.255.0');
  });
  it('should create IPv6 mask', () => {
    assert.equal(ip.fromPrefixLen(64), 'ffff:ffff:ffff:ffff::');
  });
  it('should create IPv6 mask explicitly', () => {
    assert.equal(ip.fromPrefixLen(24, 'IPV6'), 'ffff:ff00::');
  });
  it('should throw on out-of-range prefix length', () => {
    assert.throws(() => ip.fromPrefixLen(-1), /invalid prefix length/);
    assert.throws(() => ip.fromPrefixLen(129), /invalid prefix length/);
    assert.throws(() => ip.fromPrefixLen(NaN), /invalid prefix length/);
  });
});

describe('not() method', () => {
  it('should reverse bits in address', () => {
    assert.equal(ip.not('255.255.255.0'), '0.0.0.255');
  });
});

describe('or() method', () => {
  it('should or bits in ipv4 addresses', () => {
    assert.equal(ip.or('0.0.0.255', '192.168.1.10'), '192.168.1.255');
  });
  it('should or bits in ipv6 addresses', () => {
    assert.equal(
      ip.or('::ff', '::abcd:dcba:abcd:dcba'),
      '::abcd:dcba:abcd:dcff',
    );
  });
  it('should or bits in mixed addresses', () => {
    assert.equal(
      ip.or('0.0.0.255', '::abcd:dcba:abcd:dcba'),
      '::abcd:dcba:abcd:dcff',
    );
  });
});

describe('mask() method', () => {
  it('should mask bits in address', () => {
    assert.equal(ip.mask('192.168.1.134', '255.255.255.0'), '192.168.1.0');
    assert.equal(ip.mask('192.168.1.134', '::ffff:ff00'), '::ffff:c0a8:100');
  });

  it('should not leak data', () => {
    for (let i = 0; i < 10; i++) {
      assert.equal(ip.mask('::1', '0.0.0.0'), '::');
    }
  });
});

describe('subnet() method', () => {
  // Test cases calculated with http://www.subnet-calculator.com/
  const ipv4Subnet = ip.subnet('192.168.1.134', '255.255.255.192');

  it('should compute ipv4 network address', () => {
    assert.equal(ipv4Subnet.networkAddress, '192.168.1.128');
  });

  it("should compute ipv4 network's first address", () => {
    assert.equal(ipv4Subnet.firstAddress, '192.168.1.129');
  });

  it("should compute ipv4 network's last address", () => {
    assert.equal(ipv4Subnet.lastAddress, '192.168.1.190');
  });

  it('should compute ipv4 broadcast address', () => {
    assert.equal(ipv4Subnet.broadcastAddress, '192.168.1.191');
  });

  it('should compute ipv4 subnet number of addresses', () => {
    assert.equal(ipv4Subnet.length, 64);
  });

  it('should compute ipv4 subnet number of addressable hosts', () => {
    assert.equal(ipv4Subnet.numHosts, 62);
  });

  it('should compute ipv4 subnet mask', () => {
    assert.equal(ipv4Subnet.subnetMask, '255.255.255.192');
  });

  it("should compute ipv4 subnet mask's length", () => {
    assert.equal(ipv4Subnet.subnetMaskLength, 26);
  });

  it('should know whether a subnet contains an address', () => {
    assert.equal(ipv4Subnet.contains('192.168.1.180'), true);
  });

  it('should know whether a subnet does not contain an address', () => {
    assert.equal(ipv4Subnet.contains('192.168.1.195'), false);
  });

  it('should reject a plain (non-mapped) IPv6 address', () => {
    assert.throws(() => ip.subnet('2001:db8::1', '255.255.255.0'), /IPv4/);
  });
});

describe('subnet() method with mask length 32', () => {
  const ipv4Subnet = ip.subnet('192.168.1.134', '255.255.255.255');
  it("should compute ipv4 network's first address", () => {
    assert.equal(ipv4Subnet.firstAddress, '192.168.1.134');
  });
  it("should compute ipv4 network's last address", () => {
    assert.equal(ipv4Subnet.lastAddress, '192.168.1.134');
  });
  it('should compute ipv4 subnet number of addressable hosts', () => {
    assert.equal(ipv4Subnet.numHosts, 1);
  });
});

describe('subnet() method with mask length 31', () => {
  const ipv4Subnet = ip.subnet('192.168.1.134', '255.255.255.254');
  it("should compute ipv4 network's first address", () => {
    assert.equal(ipv4Subnet.firstAddress, '192.168.1.134');
  });
  it("should compute ipv4 network's last address", () => {
    assert.equal(ipv4Subnet.lastAddress, '192.168.1.135');
  });
  it('should compute ipv4 subnet number of addressable hosts', () => {
    assert.equal(ipv4Subnet.numHosts, 2);
  });
});

describe('cidrSubnet() method', () => {
  const ipv4Subnet = ip.cidrSubnet('192.168.1.134/26');

  it('should compute an ipv4 network address', () => {
    assert.equal(ipv4Subnet.networkAddress, '192.168.1.128');
  });
  it("should compute an ipv4 network's first address", () => {
    assert.equal(ipv4Subnet.firstAddress, '192.168.1.129');
  });
  it("should compute an ipv4 network's last address", () => {
    assert.equal(ipv4Subnet.lastAddress, '192.168.1.190');
  });
  it('should compute an ipv4 broadcast address', () => {
    assert.equal(ipv4Subnet.broadcastAddress, '192.168.1.191');
  });
  it('should compute an ipv4 subnet number of addresses', () => {
    assert.equal(ipv4Subnet.length, 64);
  });
  it('should compute an ipv4 subnet number of addressable hosts', () => {
    assert.equal(ipv4Subnet.numHosts, 62);
  });
  it('should compute an ipv4 subnet mask', () => {
    assert.equal(ipv4Subnet.subnetMask, '255.255.255.192');
  });
  it("should compute an ipv4 subnet mask's length", () => {
    assert.equal(ipv4Subnet.subnetMaskLength, 26);
  });
  it('should know whether a subnet contains an address', () => {
    assert.equal(ipv4Subnet.contains('192.168.1.180'), true);
  });
  it('should know whether a subnet does not contain an address', () => {
    assert.equal(ipv4Subnet.contains('192.168.1.195'), false);
  });

  it('should throw on malformed CIDR strings', () => {
    assert.throws(() => ip.cidrSubnet('192.168.1.134'), /invalid CIDR subnet/);
    assert.throws(() => ip.cidrSubnet('192.168.1.134/x'), /invalid CIDR subnet/);
    assert.throws(() => ip.cidrSubnet('192.168.1.134/33'), /invalid CIDR subnet/);
    assert.throws(() => ip.cidrSubnet('2001:db8::/129'), /invalid CIDR subnet/);
  });
});

describe('cidr() method', () => {
  it('should mask address in CIDR notation', () => {
    assert.equal(ip.cidr('192.168.1.134/26'), '192.168.1.128');
    assert.equal(ip.cidr('2607:f0d0:1002:51::4/56'), '2607:f0d0:1002::');
  });

  it('should mask an IPv6 address with a short prefix', () => {
    assert.equal(ip.cidr('2001:db8::1/32'), '2001:db8::');
  });
});

describe('isEqual() method', () => {
  it('should check if addresses are equal', () => {
    assert(ip.isEqual('127.0.0.1', '::7f00:1'));
    assert(!ip.isEqual('127.0.0.1', '::7f00:2'));
    assert(ip.isEqual('127.0.0.1', '::ffff:7f00:1'));
    assert(!ip.isEqual('127.0.0.1', '::ffaf:7f00:1'));
    assert(ip.isEqual('::ffff:127.0.0.1', '::ffff:127.0.0.1'));
    assert(ip.isEqual('::ffff:127.0.0.1', '127.0.0.1'));
  });
});

describe('normalizeToLong() method', () => {
  it('should correctly normalize "127.0.0.1"', () => {
    assert.equal(ip.normalizeToLong('127.0.0.1'), 2130706433);
  });
  it('should correctly handle "127.1" as two parts', () => {
    assert.equal(ip.normalizeToLong('127.1'), 2130706433);
  });
  it('should correctly handle "127.0.1" as three parts', () => {
    assert.equal(ip.normalizeToLong('127.0.1'), 2130706433);
  });
  it('should correctly handle hexadecimal notation "0x7f.0x0.0x0.0x1"', () => {
    assert.equal(ip.normalizeToLong('0x7f.0x0.0x0.0x1'), 2130706433);
  });
  it('should correctly handle "0x7f000001" as a single part', () => {
    assert.equal(ip.normalizeToLong('0x7f000001'), 2130706433);
  });
  it('should correctly handle octal notation "010.0.0.01"', () => {
    assert.equal(ip.normalizeToLong('010.0.0.01'), 134217729);
  });
  it('should return -1 for an invalid address "256.100.50.25"', () => {
    assert.equal(ip.normalizeToLong('256.100.50.25'), -1);
  });
  it('should return -1 for an address with invalid octal "019.0.0.1"', () => {
    assert.equal(ip.normalizeToLong('019.0.0.1'), -1);
  });
  it('should return -1 for an address with invalid hex "0xGG.0.0.1"', () => {
    assert.equal(ip.normalizeToLong('0xGG.0.0.1'), -1);
  });
  it('should return -1 for hex with trailing garbage "0x1G.0.0.1"', () => {
    assert.equal(ip.normalizeToLong('0x1G.0.0.1'), -1);
  });
  it('should return -1 for an empty string', () => {
    assert.equal(ip.normalizeToLong(''), -1);
  });
  it('should return -1 for a string with too many parts "192.168.0.1.100"', () => {
    assert.equal(ip.normalizeToLong('192.168.0.1.100'), -1);
  });
  it('should return -1 for a single part above 2^32 - 1', () => {
    assert.equal(ip.normalizeToLong('4294967296'), -1);
  });
});

describe('isPrivate() method', () => {
  it('should check if an address is localhost', () => {
    assert.equal(ip.isPrivate('127.0.0.1'), true);
  });

  it('should check if an address is from a 192.168.x.x network', () => {
    assert.equal(ip.isPrivate('192.168.0.123'), true);
    assert.equal(ip.isPrivate('192.168.122.123'), true);
    assert.equal(ip.isPrivate('192.162.1.2'), false);
  });

  it('should check if an address is from a 172.16.x.x network', () => {
    assert.equal(ip.isPrivate('172.16.0.5'), true);
    assert.equal(ip.isPrivate('172.16.123.254'), true);
    assert.equal(ip.isPrivate('171.16.0.5'), false);
    assert.equal(ip.isPrivate('172.25.232.15'), true);
    assert.equal(ip.isPrivate('172.15.0.5'), false);
    assert.equal(ip.isPrivate('172.32.0.5'), false);
  });

  it('should check if an address is from a 169.254.x.x network', () => {
    assert.equal(ip.isPrivate('169.254.2.3'), true);
    assert.equal(ip.isPrivate('169.254.221.9'), true);
    assert.equal(ip.isPrivate('168.254.2.3'), false);
  });

  it('should check if an address is from a 10.x.x.x network', () => {
    assert.equal(ip.isPrivate('10.0.2.3'), true);
    assert.equal(ip.isPrivate('10.1.23.45'), true);
    assert.equal(ip.isPrivate('12.1.2.3'), false);
  });

  it('should check if an address is from a private IPv6 network', () => {
    assert.equal(ip.isPrivate('fd12:3456:789a:1::1'), true);
    assert.equal(ip.isPrivate('fe80::f2de:f1ff:fe3f:307e'), true);
    assert.equal(ip.isPrivate('::ffff:10.100.1.42'), true);
    assert.equal(ip.isPrivate('::FFFF:172.16.200.1'), true);
    assert.equal(ip.isPrivate('::ffff:192.168.0.1'), true);
  });

  it('should check if an address is from the internet', () => {
    assert.equal(ip.isPrivate('165.225.132.33'), false); // joyent.com
  });

  it('should check unspecified and loopback IPv6 addresses', () => {
    assert.equal(ip.isPrivate('::'), true);
    assert.equal(ip.isPrivate('::1'), true);
    assert.equal(ip.isPrivate('fe80::1'), true);
  });
});

describe('loopback() method', () => {
  it('should respond with 127.0.0.1 by default', () => {
    assert.equal(ip.loopback(), '127.0.0.1');
  });
  it('should respond with 127.0.0.1 for ipv4', () => {
    assert.equal(ip.loopback('ipv4'), '127.0.0.1');
  });
  it('should respond with ::1 for ipv6', () => {
    // the original returned fe80::1, which is link-local, not loopback
    assert.equal(ip.loopback('ipv6'), '::1');
  });
});

describe('isLoopback() method', () => {
  it('should respond with true for 127.0.0.1', () => {
    assert.ok(ip.isLoopback('127.0.0.1'));
  });
  it('should respond with true for 127.8.8.8', () => {
    assert.ok(ip.isLoopback('127.8.8.8'));
  });
  it('should respond with false for 8.8.8.8', () => {
    assert.equal(ip.isLoopback('8.8.8.8'), false);
  });
  it('should respond with true for ::1', () => {
    assert.ok(ip.isLoopback('::1'));
  });
  it('should respond with false for 192.168.1.1', () => {
    assert.equal(ip.isLoopback('192.168.1.1'), false);
  });
});

describe('address() method', () => {
  it('should respond with a private ip by default', () => {
    assert.ok(ip.isPrivate(ip.address()));
  });

  [undefined, 'ipv4', 'ipv6'].forEach((family) => {
    it(`should respond with a private ip for family ${family}`, () => {
      const addr = ip.address('private', family);
      // machines without a non-loopback address of this family fall back
      // to the loopback address, which is private as well
      assert.ok(ip.isPrivate(addr));
    });
  });

  it('should return undefined for an unknown interface', () => {
    assert.equal(ip.address('no-such-interface-000'), undefined);
  });

  const interfaces = os.networkInterfaces();

  Object.keys(interfaces).forEach((nic) => {
    [undefined, 'ipv4'].forEach((family) => {
      it(`should respond with an ipv4 address for ${nic} (${family})`, () => {
        const addr = ip.address(nic, family);
        assert.ok(!addr || net.isIPv4(addr));
      });
    });

    it(`should respond with an ipv6 address for ${nic}`, () => {
      const addr = ip.address(nic, 'ipv6');
      assert.ok(!addr || net.isIPv6(addr.split('%')[0]));
    });
  });
});

describe('toLong() method', () => {
  it('should respond with a int', () => {
    assert.equal(ip.toLong('127.0.0.1'), 2130706433);
    assert.equal(ip.toLong('255.255.255.255'), 4294967295);
  });
  it('should throw on malformed input', () => {
    assert.throws(() => ip.toLong('127.1'), /Invalid ip address/);
    assert.throws(() => ip.toLong('256.0.0.1'), /Invalid ip address/);
  });
});

describe('fromLong() method', () => {
  it('should respond with ipv4 address', () => {
    assert.equal(ip.fromLong(2130706433), '127.0.0.1');
    assert.equal(ip.fromLong(4294967295), '255.255.255.255');
  });
  it('should throw on out-of-range values', () => {
    assert.throws(() => ip.fromLong(-1), /Invalid long value/);
    assert.throws(() => ip.fromLong(4294967296), /Invalid long value/);
    assert.throws(() => ip.fromLong(1.5), /Invalid long value/);
  });
});
