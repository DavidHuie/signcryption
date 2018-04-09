package aalsigncryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"hash"
	"io"
	"math/big"
)

type PublicKey struct {
	Curve elliptic.Curve
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
	securityLevel int
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
	nMod := s.curve.Params().N

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
	p := new(big.Int).Add(v, source.V)
	p.Mod(p, nMod)

	// compute Q
	xQ, yQ := s.curve.ScalarMult(dest.X, dest.Y, p.Bytes())

	// compute session key
	hash := s.hashCreator()
	hash.Write(xQ.Bytes())
	hash.Write(source.X.Bytes())
	hash.Write(yQ.Bytes())
	hash.Write(dest.X.Bytes())
	key := hash.Sum(nil)
	key = key[:s.securityLevel/8]

	// fmt.Printf("xQ: %x\n", xQ.Bytes())
	// fmt.Printf("source x: %x\n", source.X.Bytes())
	// fmt.Printf("yQ: %x\n", yQ.Bytes())
	// fmt.Printf("dest x: %x\n", dest.X.Bytes())
	// fmt.Printf("key: %x\n", key)

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
	hash = s.hashCreator()
	hash.Write(additionalData)
	hash.Write(iv)
	hash.Write(ciphertext)
	hash.Write(xR.Bytes())
	hash.Write(source.X.Bytes())
	hash.Write(yR.Bytes())
	hash.Write(dest.X.Bytes())
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
	iv := output.Ciphertext[:aes.BlockSize]
	ciphertext := output.Ciphertext[aes.BlockSize:]

	// compute tag
	hash := s.hashCreator()
	hash.Write(output.AdditionalData)
	hash.Write(iv)
	hash.Write(ciphertext)
	hash.Write(xR.Bytes())
	hash.Write(source.X.Bytes())
	hash.Write(yR.Bytes())
	hash.Write(dest.X.Bytes())
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

	// compute p & q
	xP, yP := s.curve.Add(xR, yR, source.X, source.Y)
	xQ, yQ := s.curve.ScalarMult(xP, yP, dest.V.Bytes())

	// compute session key
	hash := s.hashCreator()
	hash.Write(xQ.Bytes())
	hash.Write(source.X.Bytes())
	hash.Write(yQ.Bytes())
	hash.Write(dest.X.Bytes())
	key := hash.Sum(nil)
	key = key[:s.securityLevel/8]

	// fmt.Printf("xQ: %x\n", xQ.Bytes())
	// fmt.Printf("source x: %x\n", source.X.Bytes())
	// fmt.Printf("yQ: %x\n", yQ.Bytes())
	// fmt.Printf("dest x: %x\n", dest.X.Bytes())
	// fmt.Printf("key: %x\n", key)

	// extract IV
	iv := output.Ciphertext[:aes.BlockSize]
	ciphertext := output.Ciphertext[aes.BlockSize:]

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

// NewP256 returns a Signcrypter based on the elliptic curve P256. The
// signcrypter also uses AES-CTR-128 for encrypting and SHA-256 for
// generating keys. This signcryption scheme provides security at the
// 128-bit level.
func NewP256() Signcrypter {
	return newP256(rand.Reader)
}

func newP256(rand io.Reader) Signcrypter {
	return &signcrypter{
		securityLevel: 128,
		curve:         elliptic.P256(),
		hashCreator:   sha256.New,
		cipherCreator: aes.NewCipher,
		rand:          rand,
	}
}

// NewP521 returns a Signcrypter based on the elliptic curve P521. The
// signcrypter also uses AES-CTR-512 for encrypting and SHA-512 for
// generating keys. This signcryption scheme provides security at the
// 256-bit level.
func NewP521() Signcrypter {
	return newP521(rand.Reader)
}

func newP521(rand io.Reader) Signcrypter {
	return &signcrypter{
		securityLevel: 256,
		curve:         elliptic.P521(),
		hashCreator:   sha256.New,
		cipherCreator: aes.NewCipher,
		rand:          rand,
	}
}
