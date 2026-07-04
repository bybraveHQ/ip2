'use strict';

// Regression suite for CVE-2024-29415 / GHSA-2p57-rm9w-gvfp and the strict
// parsing behaviour introduced in the fork.

const assert = require('node:assert');
const { describe, it } = require('node:test');
const ip = require('..');

// Every PoC vector from GHSA-2p57-rm9w-gvfp: the original classified these as
// public. The fork refuses to classify non-canonical spellings at all —
// throwing beats silently guessing wrong when the caller is using the answer
// to guard outgoing requests.
describe('CVE-2024-29415: malformed addresses throw instead of passing as public', () => {
  ['127.1', '127.0.1', '127.00.0x1', '127.0.0x0.1', '01200034567', '012.1.2.3', '0x7f.1', '0177.0.0.1', '0x7f.0.0.1', '2130706433'].forEach((addr) => {
    it(`isPrivate("${addr}") throws`, () => {
      assert.throws(() => ip.isPrivate(addr), /Invalid ip address/);
    });
    it(`isPublic("${addr}") throws`, () => {
      assert.throws(() => ip.isPublic(addr), /Invalid ip address/);
    });
    it(`isLoopback("${addr}") throws`, () => {
      assert.throws(() => ip.isLoopback(addr), /Invalid ip address/);
    });
  });

  it('non-canonical IPv6 spellings of ::1 are recognized as loopback', () => {
    // the original regexes missed these
    assert.equal(ip.isLoopback('000:0:0000::01'), true);
    assert.equal(ip.isLoopback('000:0:0000:0:000:0:00:001'), true);
    assert.equal(ip.isPrivate('000:0:0000::01'), true);
  });

  it('IPv4-mapped loopback is recognized regardless of case', () => {
    assert.equal(ip.isLoopback('::fFFf:127.0.0.1'), true);
    assert.equal(ip.isPrivate('::fFFf:127.0.0.1'), true);
    assert.equal(ip.isPublic('::fFFf:127.0.0.1'), false);
  });

  it('non-canonical IPv6 spellings of private ranges are recognized', () => {
    assert.equal(ip.isPrivate('fe80::0001'), true);
    assert.equal(ip.isPrivate('0:0:0:0:0:ffff:a00:1'), true); // ::ffff:10.0.0.1
  });
});

describe('strict format checks', () => {
  it('isV4Format rejects malformed and non-canonical addresses', () => {
    assert.equal(ip.isV4Format('127.0.0.1'), true);
    assert.equal(ip.isV4Format('0.0.0.0'), true);
    assert.equal(ip.isV4Format('255.255.255.255'), true);
    // #105: octets above 255
    assert.equal(ip.isV4Format('300.1.2.3'), false);
    assert.equal(ip.isV4Format('256.0.0.1'), false);
    assert.equal(ip.isV4Format('127.1'), false);
    assert.equal(ip.isV4Format('127.0.0.01'), false); // leading zero = ambiguous octal
    assert.equal(ip.isV4Format('0x7f.0.0.1'), false);
    assert.equal(ip.isV4Format('1.2.3.4.5'), false);
    assert.equal(ip.isV4Format(''), false);
  });

  it('isV6Format rejects IPv4 addresses (#67)', () => {
    assert.equal(ip.isV6Format('127.0.0.1'), false);
    assert.equal(ip.isV6Format('1.2.3.4'), false);
  });

  it('isV6Format accepts valid IPv6 addresses', () => {
    assert.equal(ip.isV6Format('::1'), true);
    assert.equal(ip.isV6Format('::'), true);
    assert.equal(ip.isV6Format('2001:db8::1'), true);
    assert.equal(ip.isV6Format('::ffff:127.0.0.1'), true);
    assert.equal(ip.isV6Format('1:2:3:4:5:6:7:8'), true);
    assert.equal(ip.isV6Format('fe80::1%en0'), true); // zone id
  });

  it('isV6Format rejects malformed IPv6 addresses', () => {
    assert.equal(ip.isV6Format('1:2:3:4:5:6:7:8:9'), false);
    assert.equal(ip.isV6Format('1::2::3'), false);
    assert.equal(ip.isV6Format('1:2:3:4:5:6:7'), false);
    assert.equal(ip.isV6Format('12345::'), false);
    assert.equal(ip.isV6Format('g::1'), false);
    assert.equal(ip.isV6Format('::1%'), false);
    assert.equal(ip.isV6Format('1.2.3.4::'), false);
  });

  it('isValid accepts either family and rejects everything else', () => {
    assert.equal(ip.isValid('8.8.8.8'), true);
    assert.equal(ip.isValid('2001:db8::1'), true);
    assert.equal(ip.isValid('127.1'), false);
    assert.equal(ip.isValid('hello'), false);
    assert.equal(ip.isValid(undefined), false);
    assert.equal(ip.isValid(2130706433), false);
  });
});

describe('full special-purpose range coverage (IPv4)', () => {
  const nonGlobal = [
    '0.1.2.3', // 0.0.0.0/8
    '10.0.0.1',
    '100.64.0.1', '100.127.255.254', // CGNAT
    '127.255.255.255',
    '169.254.1.1',
    '172.16.0.1', '172.31.255.254',
    '192.0.0.1', // IETF protocol assignments
    '192.0.2.1', // TEST-NET-1
    '192.88.99.1', // 6to4 relay
    '192.168.0.1',
    '198.18.0.1', '198.19.255.254', // benchmarking
    '198.51.100.1', // TEST-NET-2
    '203.0.113.1', // TEST-NET-3
    '224.0.0.1', // multicast
    '240.0.0.1', // reserved
    '255.255.255.255', // broadcast
  ];
  nonGlobal.forEach((addr) => {
    it(`${addr} is private`, () => {
      assert.equal(ip.isPrivate(addr), true);
      assert.equal(ip.isPublic(addr), false);
    });
  });

  const globals = [
    '8.8.8.8', '1.1.1.1', '100.63.255.254', '100.128.0.1',
    '192.0.1.1', '192.0.3.1', '198.17.255.255', '198.20.0.1',
    '203.0.114.1', '223.255.255.255', '9.255.255.255', '11.0.0.1',
  ];
  globals.forEach((addr) => {
    it(`${addr} is public`, () => {
      assert.equal(ip.isPublic(addr), true);
    });
  });
});

describe('full special-purpose range coverage (IPv6)', () => {
  const nonGlobal = [
    '::', '::1',
    'fc00::1', 'fd12:3456::1', // ULA
    'fe80::1', 'febf::1', // link-local
    'fec0::1', // site-local (deprecated)
    'ff02::1', // multicast
    '100::1', // discard-only
    '2001::1', // Teredo (IETF protocol assignments block)
    '2001:2::1', // benchmarking
    '2001:10::1', '2001:20::1', // ORCHID
    '2001:db8::1', // documentation
    '3fff::1', '3fff:fff:ffff::1', // documentation (RFC 9637)
    '5f00::1', // SRv6 SIDs
    '64:ff9b:1::1', // local-use NAT64
  ];
  nonGlobal.forEach((addr) => {
    it(`${addr} is private`, () => {
      assert.equal(ip.isPrivate(addr), true);
    });
  });

  const globals = [
    '2606:4700:4700::1111', // cloudflare
    '2620:fe::fe', // quad9
    '2600::1',
  ];
  globals.forEach((addr) => {
    it(`${addr} is public`, () => {
      assert.equal(ip.isPublic(addr), true);
    });
  });

  it('classifies transition addresses by their embedded IPv4 address', () => {
    // IPv4-mapped
    assert.equal(ip.isPrivate('::ffff:10.0.0.1'), true);
    assert.equal(ip.isPublic('::ffff:8.8.8.8'), true);
    // NAT64
    assert.equal(ip.isPublic('64:ff9b::8.8.8.8'), true);
    assert.equal(ip.isPrivate('64:ff9b::10.0.0.1'), true);
    // 6to4
    assert.equal(ip.isPublic('2002:808:808::1'), true); // embedded 8.8.8.8
    assert.equal(ip.isPrivate('2002:c0a8:101::1'), true); // embedded 192.168.1.1
  });

  it('ignores zone ids when classifying', () => {
    assert.equal(ip.isPrivate('fe80::1%en0'), true);
    assert.equal(ip.isLoopback('::1%lo0'), true);
  });
});

describe('isLoopback() corrections', () => {
  it('fe80::1 is link-local, not loopback (original said true)', () => {
    assert.equal(ip.isLoopback('fe80::1'), false);
    assert.equal(ip.isPrivate('fe80::1'), true); // still private
  });

  it(':: is unspecified, not loopback (original said true)', () => {
    assert.equal(ip.isLoopback('::'), false);
    assert.equal(ip.isPrivate('::'), true); // still private
  });

  it('IPv4-mapped 127.0.0.0/8 is loopback', () => {
    assert.equal(ip.isLoopback('::ffff:127.0.0.1'), true);
    assert.equal(ip.isLoopback('::ffff:127.255.255.254'), true);
    assert.equal(ip.isLoopback('::ffff:128.0.0.1'), false);
  });
});

describe('cidrSubnet().contains() with IPv4-mapped addresses (#104)', () => {
  it('finds a mapped address inside an IPv4 subnet', () => {
    const subnet = ip.cidrSubnet('108.162.192.0/18');
    assert.equal(subnet.contains('::ffff:108.162.245.126'), true);
    assert.equal(subnet.contains('108.162.245.126'), true);
    assert.equal(subnet.contains('::ffff:108.163.0.1'), false);
  });

  it('returns false (never throws) for malformed input', () => {
    const subnet = ip.cidrSubnet('10.0.0.0/8');
    assert.equal(subnet.contains('not-an-ip'), false);
    assert.equal(subnet.contains('10.1'), false);
    assert.equal(subnet.contains('2001:db8::1'), false);
  });

  it('accepts an IPv4-mapped subnet base address', () => {
    const subnet = ip.subnet('::ffff:192.168.1.134', '255.255.255.192');
    assert.equal(subnet.networkAddress, '192.168.1.128');
  });
});

describe('address() direction fix', () => {
  it("address('public') never returns a private address unless it is the loopback fallback", () => {
    const addr = ip.address('public');
    // either a genuinely public address, or the documented loopback fallback
    assert.ok(ip.isPublic(addr) || addr === '127.0.0.1');
  });
});
