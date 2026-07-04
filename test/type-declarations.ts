import ip, {
  SubnetInfo,
  toBuffer,
  isPrivate,
  cidrSubnet,
  address,
  fromPrefixLen,
} from '../index';

const buf: Buffer = toBuffer('127.0.0.1');
const buf2: Buffer = ip.toBuffer('::1', buf, 0);
const s: string = ip.toString(buf2, 0, 16);

const b1: boolean = ip.isV4Format('127.0.0.1');
const b2: boolean = ip.isV6Format('::1');
const b3: boolean = ip.isValid('8.8.8.8');
const b4: boolean = isPrivate('10.0.0.1');
const b5: boolean = ip.isPublic('8.8.8.8');
const b6: boolean = ip.isLoopback('127.0.0.1');
const b7: boolean = ip.isEqual('127.0.0.1', '::ffff:7f00:1');

const m1: string = fromPrefixLen(24);
const m2: string = ip.fromPrefixLen(64, 'ipv6');
const m3: string = ip.fromPrefixLen(64, 6);
const m4: string = ip.mask('192.168.1.134', '255.255.255.0');
const m5: string = ip.cidr('192.168.1.134/26');
const m6: string = ip.not('255.255.255.0');
const m7: string = ip.or('0.0.0.255', '192.168.1.10');

const sub: SubnetInfo = ip.subnet('192.168.1.134', '255.255.255.192');
const sub2: SubnetInfo = cidrSubnet('192.168.1.134/26');
const contained: boolean = sub.contains('192.168.1.180');
const hosts: number = sub2.numHosts;

const lo: string = ip.loopback('ipv6');
const addr1: string | undefined = address();
const addr2: string | undefined = address('public', 'ipv4');
const addr3: string | undefined = ip.address('eth0', 6);

const long: number = ip.toLong('127.0.0.1');
const fromL: string = ip.fromLong(2130706433);
const norm: number = ip.normalizeToLong('127.1');

// keep tsc from flagging unused locals in this declaration smoke test
void [s, b1, b2, b3, b4, b5, b6, b7, m1, m2, m3, m4, m5, m6, m7, contained, hosts, lo, addr1, addr2, addr3, long, fromL, norm];
