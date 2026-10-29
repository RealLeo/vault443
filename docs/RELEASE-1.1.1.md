# Vault 443 1.1.1

OpenVPN imports now accept IPv6 server addresses enclosed in brackets, such as
`remote [2001:db8::42] 443 tcp6-client`. The importer removes only the IPv6
brackets before validation and storage. IPv4 fallback servers, remote order,
transports and cryptographic settings are preserved.

Bracketed and bare forms produce the same profile ID. Existing accepted profiles
keep their IDs. Invalid brackets, bracketed hostnames/IPv4, embedded ports,
scoped addresses and prohibited destinations remain rejected.

Regression checks cover parsing, identity, persistence, malformed addresses and
the real Qt/private D-Bus import path with generated credentials. The reported
user profile passes a read-only import check; it is not copied into test data,
and no connection to the corporate server is made during development.

Packages are provided for amd64 and ARM64 (cross-build). Network policy, existing
data formats and the pinned Xray core are unchanged from 1.1.0.
