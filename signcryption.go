package signcryption

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// PublicKey represents a signcryption public key, which is just an
// elliptic curve point behind the scenes. In order to be useful, the
// ID field has to be filled in by an out-of-band process and be
// unique to each public key.
type PublicKey struct {
	Curve elliptic.Curve
	X, Y  *big.Int
	ID    []byte
}

// Validate validates a public key.
func (p *PublicKey) Validate() error {
	if len(p.ID) == 0 {
		return errors.New("error: missing public key ID")
	}
	return nil
}

// PrivateKey represents an AAL public key, which is a PublicKey point
// and an integer.
type PrivateKey struct {
	PublicKey
	V *big.Int
}

// ToECDSA converts a key to ECDSA format.
func (p *PrivateKey) ToECDSA() *ecdsa.PrivateKey {
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: p.Curve,
			X:     p.X,
			Y:     p.Y,
		},
		D: p.V,
	}
}

// GeneratePrivateKey generates a public key for an elliptic curve.
func GeneratePrivateKey(c elliptic.Curve, rand io.Reader) (*PrivateKey, error) {
	ecdsaKey, err := ecdsa.GenerateKey(c, rand)
	if err != nil {
		return nil, fmt.Errorf("error generating ECDSA key: %s", err)
	}

	return PrivateKeyFromECDSA(ecdsaKey, nil), nil
}

// PrivateKeyFromECDSA generates a PrivateKey from an ECDSA private
// key.
func PrivateKeyFromECDSA(k *ecdsa.PrivateKey, id []byte) *PrivateKey {
	return &PrivateKey{
		PublicKey: PublicKey{
			Curve: k.Curve,
			X:     k.X,
			Y:     k.Y,
			ID:    id,
		},
		V: k.D,
	}
}

// PublicKeyFromECDSA generates a PublicKey from an ECDSA public key.
func PublicKeyFromECDSA(k *ecdsa.PublicKey, id []byte) *PublicKey {
	return &PublicKey{
		Curve: k.Curve,
		X:     k.X,
		Y:     k.Y,
		ID:    id,
	}
}
