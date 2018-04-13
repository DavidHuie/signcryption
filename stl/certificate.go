package stl

import (
	"crypto/ecdsa"

	"github.com/DavidHuie/signcryption"
)

// Certificate describes the information that identifies each unique
// user of STL. Certificates should be validated externally.
type Certificate struct {
	ID                   []byte
	HandshakePrivateKey  *ecdsa.PrivateKey
	EncryptionPrivateKey *signcryption.PrivateKey
}
