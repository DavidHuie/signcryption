# signcryption

A collection of signcryption algorithms for Go.

## Algorithms

### Ahmad-Afzal-Iqbal

[AAL](http://ieeexplore.ieee.org/document/6725326/)
(Ahmad-Afzal-Iqbal) is an elliptic curve signcryption scheme designed
for firewalls. AAL signcryption provides signatures that can be
publically verified without revealing the contents of the
ciphertext. In contrast, most signcryption schemes provide signature
verification as part of the decryption process and not as a separate
process.

AAL signcryption provides the following features:
- confidentiality
- message integrity
- signature unforgeability
- non-repudiation
- public verification
- ciphertext-only authentication
- forward secrecy

This version of AAL is implemented with the elliptic curves P256 &
P521, AES counter mode encryption, and SHA-256 for generating keys.

### encrypt-and-sign-then-sign

- AES-GCM
- ECDSA
