package signcryption

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"io"

	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack"
)

var (
	// StandardCurve is the curve we use for all elliptic curve
	// operations.
	StandardCurve = elliptic.P256()
)

// Certificate describes the information that identifies each unique
// user of STL. Certificates should be validated externally.
type Certificate struct {
	ID                   []byte
	EncryptionPrivateKey *ecdsa.PrivateKey
	EncryptionPublicKey  *ecdsa.PublicKey
	HandshakePrivateKey  *ecdsa.PrivateKey
	HandshakePublicKey   *ecdsa.PublicKey
}

// Validate validates a certificate
func (c *Certificate) Validate() error {
	if len(c.ID) == 0 {
		return errors.New("error: missing ID field")
	}
	return nil
}

type marshalCert struct {
	ID                  []byte
	HandshakePublicKey  []byte
	EncryptionPublicKey []byte
}

// Marshal marshals a certificate into bytes.
func (c *Certificate) Marshal() ([]byte, error) {
	hpk := elliptic.Marshal(
		c.HandshakePublicKey.Curve,
		c.HandshakePublicKey.X,
		c.HandshakePublicKey.Y,
	)
	epk := elliptic.Marshal(
		c.EncryptionPublicKey.Curve,
		c.EncryptionPublicKey.X,
		c.EncryptionPublicKey.Y,
	)

	m := &marshalCert{
		ID:                  c.ID,
		HandshakePublicKey:  hpk,
		EncryptionPublicKey: epk,
	}

	return msgpack.Marshal(m)
}

// UnmarshalCertificate parses out a certificate from a slice of
// bytes.
func UnmarshalCertificate(b []byte) (*Certificate, error) {
	m := &marshalCert{}
	if err := msgpack.Unmarshal(b, &m); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling certificate")
	}

	hpkX, hpkY := elliptic.Unmarshal(StandardCurve, m.HandshakePublicKey)
	epkX, epkY := elliptic.Unmarshal(StandardCurve, m.EncryptionPublicKey)

	hpk := &ecdsa.PublicKey{
		Curve: StandardCurve,
		X:     hpkX,
		Y:     hpkY,
	}
	epk := &ecdsa.PublicKey{
		Curve: StandardCurve,
		X:     epkX,
		Y:     epkY,
	}

	return &Certificate{
		ID:                  m.ID,
		HandshakePublicKey:  hpk,
		EncryptionPublicKey: epk,
	}, nil
}

// GenerateCertificate generates a random certificate. The certificate
// still needs an ID field which should be produced by an external
// entity.
func GenerateCertificate(rand io.Reader) (*Certificate, error) {
	h, err := ecdsa.GenerateKey(StandardCurve, rand)
	if err != nil {
		return nil, fmt.Errorf("error generating encryption ECDSA key: %s", err)
	}
	e, err := ecdsa.GenerateKey(StandardCurve, rand)
	if err != nil {
		return nil, fmt.Errorf("error generating encryption ECDSA key: %s", err)
	}

	return &Certificate{
		HandshakePublicKey:   &h.PublicKey,
		EncryptionPublicKey:  &e.PublicKey,
		HandshakePrivateKey:  h,
		EncryptionPrivateKey: e,
	}, nil
}
