# signcryption

[![GoDoc](https://godoc.org/github.com/DavidHuie/signcryption?status.svg)](https://godoc.org/github.com/DavidHuie/signcryption)

A collection of signcryption algorithms and protocols for Go based
around the AAL signcryption scheme.

## Algorithms

### Ahmad-Afzal-Iqbal (AAL)

[Ahmad-Afzal-Iqbal
signcryption](http://ieeexplore.ieee.org/document/6725326/) is an
elliptic curve signcryption scheme designed for firewalls. AAL
provides signatures that can be publically verified without revealing
the contents of the ciphertext. In contrast, most signcryption schemes
provide signature verification as part of the decryption process and
not as a separate process.

AAL signcryption provides the following features in unison:
- confidentiality
- message integrity
- signature unforgeability
- non-repudiation
- public verification
- ciphertext-only authentication
- forward secrecy

This version of AAL is implemented with the elliptic curves P256 &
P521, AES counter mode encryption, and SHA-256 for generating keys.

## Protocols

### Signcrypted Transport Layer (STL)

A transport layer similar to TLS that uses AAL signcryption. Used
plainly, STL offers the same guarantees as TLS with client
authentication. However, STL also includes support for a "relayer,"
which is untrusted, third party proxy that can sit in between a
client-server connection, cryptographically verifying the origin and
destination of each traffic segment. A relayer can provide NAT
traversal, firewalling, and other services.
