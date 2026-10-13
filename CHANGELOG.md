# Changelog

Maintained fork of [indutny/node-ip](https://github.com/indutny/node-ip). All notable changes to `@bybrave/ip2` are documented in this file.

## 3.1.0 — 2026-10-14

### Added

- IPv6 subnet math in `subnet()` and `cidrSubnet()`: network and last address, prefix length, address count and `contains()` for IPv6 prefixes. The original compared only the low 32 bits, so `2001:db8:f53b::/48` "contained" `2001:db8:f53a::1` ([#89](https://github.com/indutny/node-ip/issues/89), [#110](https://github.com/indutny/node-ip/issues/110)).
- `browser` field mapping `os` away, so bundlers such as webpack 5 no longer fail to resolve it ([#127](https://github.com/indutny/node-ip/issues/127), [#132](https://github.com/indutny/node-ip/issues/132)).

### Documentation

- How invalid input is handled and how to guard untrusted input ([#146](https://github.com/indutny/node-ip/issues/146)).
- Using the library in a browser bundle.

## 3.0.0 — 2026-07-05

### Security

- Fix the unpatched SSRF advisory **CVE-2024-29415 / GHSA-2p57-rm9w-gvfp** (#136/#150/#153/#158). The original classified addresses by running regular expressions over the raw string, so octal, hexadecimal and shortened forms slipped through `isPublic`/`isPrivate` and were treated as public. Addresses are now parsed strictly into bytes and classified against the full IANA special-purpose registries; non-canonical forms are rejected (fail closed). Transition ranges (IPv4-mapped, NAT64, 6to4) are classified by their embedded IPv4.

### Added

- TypeScript type definitions.
- ESM entry point alongside CommonJS.
- `isValid()` helper.

### Fixed

- `#104` — `cidrSubnet`/`contains` for IPv4-mapped IPv6 addresses.
- `#67` — `isV6Format` no longer returns `true` for plain IPv4 addresses.
- `#105` — reject IPv4 addresses with octets greater than 255.
- Correct the inverted result of `address('public')`.
- `loopback('ipv6')` now returns `::1`.
- Validate CIDR prefix lengths.
- Throw a `TypeError` on an unknown network interface.
