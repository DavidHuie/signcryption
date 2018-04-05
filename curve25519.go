package aalsigncryption

import (
	"crypto/elliptic"
	"math/big"

	gocurve25519 "golang.org/x/crypto/curve25519"
)

var (
	ecCurve25519 *curve25519
)

// curve25519 is a type that wraps an external implementation of
// Curve25519 so that it adheres to the interface elliptic.Curve.
type curve25519 struct {
	p *big.Int
}

func newCurve25519() *curve25519 {
	p, ok := new(big.Int).SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
	if !ok {
		panic("could not parse p")
	}
	return &curve25519{
		p: p,
	}
}

func (c *curve25519) Params() *elliptic.CurveParams {
	return &elliptic.CurveParams{
		P:       c.p,
		BitSize: 256,
		// All other fields are unused
	}
}

func (c *curve25519) IsOnCurve(x *big.Int, y *big.Int) bool {
	panic("not implemented")
}

func (c *curve25519) Add(x1 *big.Int, y1 *big.Int, x2 *big.Int, y2 *big.Int) (x *big.Int, y *big.Int) {
	panic("not implemented")
}

func (c *curve25519) Double(x1 *big.Int, y1 *big.Int) (x *big.Int, y *big.Int) {
	panic("not implemented")
}

func (c *curve25519) ScalarMult(x1 *big.Int, _ *big.Int, k []byte) (x *big.Int, y *big.Int) {
	dst := [32]byte{}
	in := [32]byte{}
	base := [32]byte{}
	copy(in[:], x1.Bytes())
	copy(base[:], k)

	gocurve25519.ScalarMult(&dst, &in, &base)

	return new(big.Int).SetBytes(dst[:]), nil
}

func (c *curve25519) ScalarBaseMult(k []byte) (x *big.Int, y *big.Int) {
	dst := [32]byte{}
	kAry := [32]byte{}
	copy(kAry[:], k)

	gocurve25519.ScalarBaseMult(&dst, &kAry)

	return new(big.Int).SetBytes(dst[:]), nil
}

func init() {
	ecCurve25519 = newCurve25519()
}
