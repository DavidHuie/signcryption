# signcryption

A collection of signcryption algorithms for Go.

## Algorithms

### AAL

[AAL](http://ieeexplore.ieee.org/document/6725326/)
(Ahmad-Afzal-Iqbal) is an elliptic curve signcryption scheme for
firewalls. AAL signcryption provides signatures that can be publically
verified without revealing the contents of the ciphertext. In
contrast, most signcryption schemes provide signature verification as
part of the decryption process and not as a separate process.