package aalsigncryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"hash"
	"io"
	"math/big"
)

type PublicKey struct {
	Curve elliptic.Curve
	ID    []byte
	X, Y  *big.Int
}

type PrivateKey struct {
	PublicKey
	V *big.Int
}

type Signcrypter interface {
	Signcrypt(source *PrivateKey, dest *PublicKey, plaintext, additionalData []byte) (*SigncryptionOutput, error)
	Verify(source, dest *PublicKey, output *SigncryptionOutput) bool
	Unsigncrypt(source *PublicKey, dest *PrivateKey, output *SigncryptionOutput) ([]byte, bool, error)
}

func GeneratePrivateKey(c elliptic.Curve, rand io.Reader) (*PrivateKey, error) {
	ecdsaKey, err := ecdsa.GenerateKey(c, rand)
	if err != nil {
		return nil, fmt.Errorf("error generating ECDSA key: %s", err)
	}

	return &PrivateKey{
		PublicKey: PublicKey{
			Curve: c,
			X:     ecdsaKey.X,
			Y:     ecdsaKey.Y,
		},
		V: ecdsaKey.D,
	}, nil
}

type cipherCreator func([]byte) (cipher.Block, error)

type hashCreator func() hash.Hash

type signcrypter struct {
	blockSize     int
	curve         elliptic.Curve
	hashCreator   hashCreator
	cipherCreator cipherCreator
	rand          io.Reader
}

type SigncryptionOutput struct {
	AdditionalData []byte
	R              []byte
	Ciphertext     []byte
	Signature      []byte
}

func (s *signcrypter) Signcrypt(source *PrivateKey, dest *PublicKey, plaintext, additionalData []byte) (*SigncryptionOutput, error) {
	prime := s.curve.Params().P

	// choose random v
	vBytes := make([]byte, s.curve.Params().BitSize/8)
	if _, err := io.ReadFull(s.rand, vBytes); err != nil {
		return nil, fmt.Errorf("error reading from rand reader")
	}
	v := new(big.Int).SetBytes(vBytes)
	v.Mod(v, new(big.Int).Sub(prime, big.NewInt(1)))

	// compute r
	xR, yR := s.curve.ScalarBaseMult(v.Bytes())
	rMarshaled := elliptic.Marshal(s.curve, xR, yR)

	// compute point p
	p := new(big.Int)
	p.Add(v, source.V)
	p.Mod(p, prime)

	// compute Q
	xQ, yQ := s.curve.ScalarMult(dest.X, dest.Y, p.Bytes())

	hash := s.hashCreator()

	// compute session key
	hash.Write(xQ.Bytes())
	hash.Write(source.ID)
	hash.Write(yQ.Bytes())
	hash.Write(dest.ID)
	key := hash.Sum(nil)

	// encrypt
	block, err := s.cipherCreator(key)
	if err != nil {
		return nil, fmt.Errorf("error creating AES cipher")
	}
	ciphertext := make([]byte, len(plaintext))
	iv := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(s.rand, iv); err != nil {
		return nil, fmt.Errorf("error reading random IV: %s", err)
	}
	ctr := cipher.NewCTR(block, iv)
	ctr.XORKeyStream(ciphertext, plaintext)
	ciphertext = append(iv, ciphertext...)

	// create tag
	hash.Reset()
	hash.Write(additionalData)
	hash.Write(iv)
	hash.Write(ciphertext)
	hash.Write(xR.Bytes())
	hash.Write(source.ID)
	hash.Write(yR.Bytes())
	hash.Write(dest.ID)
	t := new(big.Int).SetBytes(hash.Sum(nil))

	// create signature
	sig := new(big.Int).ModInverse(t, prime)
	sig.Mul(sig, p)
	sig.Mod(sig, prime)

	return &SigncryptionOutput{
		AdditionalData: additionalData,
		R:              rMarshaled,
		Ciphertext:     ciphertext,
		Signature:      sig.Bytes(),
	}, nil
}

func (s *signcrypter) Verify(source, dest *PublicKey, output *SigncryptionOutput) bool {
	// parse r
	xR, yR := elliptic.Unmarshal(s.curve, output.R)

	// extract IV
	iv := output.Ciphertext[:s.blockSize]
	ciphertext := output.Ciphertext[s.blockSize:]

	// compute tag
	hash := s.hashCreator()
	hash.Write(output.AdditionalData)
	hash.Write(iv)
	hash.Write(ciphertext)
	hash.Write(xR.Bytes())
	hash.Write(source.ID)
	hash.Write(yR.Bytes())
	hash.Write(dest.ID)
	t := hash.Sum(nil)

	// compute verification equation #1
	mX, mY := s.curve.ScalarBaseMult(output.Signature)
	vX1, vY1 := s.curve.ScalarMult(mX, mY, t)

	// compute verification equation #2
	vX2, vY2 := s.curve.Add(xR, yR, source.X, source.Y)

	xEqual := subtle.ConstantTimeCompare(vX1.Bytes(), vX2.Bytes())
	yEqual := subtle.ConstantTimeCompare(vY1.Bytes(), vY2.Bytes())

	return (xEqual == 0) && (yEqual == 0)
}

func (s *signcrypter) Unsigncrypt(source *PublicKey, dest *PrivateKey, output *SigncryptionOutput) ([]byte, bool, error) {
	// verify the signature first
	valid := s.Verify(source, &dest.PublicKey, output)
	if !valid {
		return nil, false, nil
	}

	// parse r
	xR, yR := elliptic.Unmarshal(s.curve, output.R)

	// extract IV
	iv := output.Ciphertext[:s.blockSize]
	ciphertext := output.Ciphertext[s.blockSize:]

	// compute p & q
	xP, yP := s.curve.Add(xR, yR, source.X, source.Y)
	xQ, yQ := s.curve.ScalarMult(xP, yP, dest.V.Bytes())

	// compute session key
	hash := s.hashCreator()
	hash.Write(xQ.Bytes())
	hash.Write(source.ID)
	hash.Write(yQ.Bytes())
	hash.Write(dest.ID)
	key := hash.Sum(nil)

	// recover plaintext
	plaintext := make([]byte, len(ciphertext))
	block, err := s.cipherCreator(key)
	if err != nil {
		return nil, false, fmt.Errorf("error creating AES cipher")
	}
	ctr := cipher.NewCTR(block, iv)
	ctr.XORKeyStream(plaintext, ciphertext)

	return plaintext, true, nil
}

// NewCurve25519 returns a Signcrypter based on the elliptic curve
// Curve25519. The signcrypter also uses AES-CTR-256 for encrypting
// and SHA-256 for generating keys. This signcryption scheme provides
// security at the 128-bit level.
func NewCurve25519() Signcrypter {
	return &signcrypter{
		blockSize:     32,
		curve:         ecCurve25519,
		hashCreator:   sha256.New,
		cipherCreator: aes.NewCipher,
		rand:          rand.Reader,
	}
}

// NewP256 returns a Signcrypter based on the elliptic curve P256. The
// signcrypter also uses AES-CTR-256 for encrypting and SHA-256 for
// generating keys. This signcryption scheme provides security at the
// 128-bit level.
func NewP256() Signcrypter {
	return &signcrypter{
		blockSize:     32,
		curve:         elliptic.P256(),
		hashCreator:   sha256.New,
		cipherCreator: aes.NewCipher,
		rand:          rand.Reader,
	}
}

// NewP521 returns a Signcrypter based on the elliptic curve P521. The
// signcrypter also uses AES-CTR-512 for encrypting and SHA-512 for
// generating keys. This signcryption scheme provides security at the
// 256-bit level.
func NewP521() Signcrypter {
	return &signcrypter{
		blockSize:     64,
		curve:         elliptic.P521(),
		hashCreator:   sha512.New,
		cipherCreator: aes.NewCipher,
		rand:          rand.Reader,
	}
}
