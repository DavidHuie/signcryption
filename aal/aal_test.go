package aalsigncryption

import (
	"bytes"
	"crypto/elliptic"
	"encoding/base64"
	"io"
	"math/rand"
	"testing"
)

const (
	plaintext = `In short: what's the fucking deal with this pizza box?
Who designed it? Where can I see more of their work?
Do they have these boxes everywhere?
Are there other pizza boxes that even come close to being this weird?`
	additionalData = `In this paper, a modified digital signcryption model has
been proposed keeping in view the requirements of firewall signcryption.
Based on this model, the security and efficiency of existing signcryption schemes
that are presented over the years have been analyzed.`

	payloadSize = 32 * 1024
)

func toBase64(in []byte) string {
	return base64.StdEncoding.EncodeToString(in)
}

func TestP256Signcrypt(t *testing.T) {
	rand := rand.New(rand.NewSource(0))

	sc := newP256(rand)
	source, err := GeneratePrivateKey(elliptic.P256(), rand)
	if err != nil {
		t.Fatal(err)
	}
	dest, err := GeneratePrivateKey(elliptic.P256(), rand)
	if err != nil {
		t.Fatal(err)
	}

	output, err := sc.Signcrypt(source, &dest.PublicKey, []byte(plaintext), []byte(additionalData))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("should encrypt correctly", func(t *testing.T) {
		if toBase64(output.Ciphertext) != `x156gb/eJ19nz+JCzzzDVGAZWihk5is6HTqW3uIb1u9GcOmjlqjfvcMUOHKQKq0o2bxor9b76645FhGw+oAQJhtLgAfBidqBv8mOcJ61s4+MLcQ77R8AHUMcd7GhNzbQTZM5isNW64jOYLQ/jyjllfCW9sZr/A0PhjXb+ioFhl1/511FofEanfd3l9OMvQZhnkBM8giTWIxBjomsfdD0hLtziWxQ0cC5P8itLj+a3PwzAi0fWNL90ZFYCNwsxxsOAVPKHrK5dtxvgpFl9R5gUutbCTp0hkC9nWlsmwXiYjm7j+O29mI=` {
			t.Log(toBase64(output.Ciphertext))
			t.Error("invalid ciphertext")
		}
		if toBase64(output.R) != `BBEyUqGsRVbGGsEsakutLpseURAHhUsEr7+SZ0Qm8uXHmoC8juTkNQ3Nx295BYMbo3MAL9EVjySeGdO90ADl3mI=` {
			t.Error("invalid r")
		}
		if toBase64(output.Signature) != `VZxdXyHHkxEgAoOXKR7A5UzZx26xN5ibHv1f14DdEoo=` {
			t.Log(toBase64(output.Signature))
			t.Error("invalid signature")
		}
		if bytes.Compare(output.AdditionalData, []byte(additionalData)) != 0 {
			t.Error("invalid additional data")
		}
	})

	t.Run("should verify", func(t *testing.T) {
		valid := sc.Verify(&source.PublicKey, &dest.PublicKey, output)
		if !valid {
			t.Error("signature should be valid")
		}
	})

	t.Run("should unsigncrypt", func(t *testing.T) {
		plaintextCandidate, valid, err := sc.Unsigncrypt(&source.PublicKey, dest, output)
		if err != nil {
			t.Error("unsigncrypting should not throw error")
		}
		if !valid {
			t.Error("signature should be valid")
		}
		if string(plaintextCandidate) != plaintext {
			t.Logf("%s", plaintextCandidate)
			t.Error("plaintext should match")
		}
	})
}

func BenchmarkSigncrypt256(b *testing.B) {
	rand := rand.New(rand.NewSource(0))

	sc := newP256(rand)
	source, err := GeneratePrivateKey(elliptic.P256(), rand)
	if err != nil {
		b.Fatal(err)
	}
	dest, err := GeneratePrivateKey(elliptic.P256(), rand)
	if err != nil {
		b.Fatal(err)
	}

	var payloads [][]byte
	for i := 0; i < b.N; i++ {
		buf := make([]byte, payloadSize)
		if _, err := io.ReadFull(rand, buf); err != nil {
			b.Fatal(err)
		}
		payloads = append(payloads, buf)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := sc.Signcrypt(source, &dest.PublicKey, []byte(plaintext), []byte(additionalData)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnsigncrypt256(b *testing.B) {
	rand := rand.New(rand.NewSource(0))

	sc := newP256(rand)
	source, err := GeneratePrivateKey(elliptic.P256(), rand)
	if err != nil {
		b.Fatal(err)
	}
	dest, err := GeneratePrivateKey(elliptic.P256(), rand)
	if err != nil {
		b.Fatal(err)
	}

	var ciphertexts []*SigncryptionOutput
	for i := 0; i < b.N; i++ {
		buf := make([]byte, payloadSize)
		if _, err := io.ReadFull(rand, buf); err != nil {
			b.Fatal(err)
		}
		ct, err := sc.Signcrypt(source, &dest.PublicKey, []byte(plaintext), []byte(additionalData))
		if err != nil {
			b.Fatal(err)
		}
		ciphertexts = append(ciphertexts, ct)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, ok, err := sc.Unsigncrypt(&source.PublicKey, dest, ciphertexts[i])
		if err != nil {
			b.Fatal(err)
		}
		if !ok {
			b.Error("not ok returned")
		}
	}
}

// func BenchmarkSigncrypt512(b *testing.B) {
// 	rand := rand.New(rand.NewSource(0))

// 	sc := newP521(rand)
// 	source, err := GeneratePrivateKey(elliptic.P256(), rand)
// 	if err != nil {
// 		b.Fatal(err)
// 	}
// 	dest, err := GeneratePrivateKey(elliptic.P256(), rand)
// 	if err != nil {
// 		b.Fatal(err)
// 	}

// 	var payloads [][]byte
// 	for i := 0; i < b.N; i++ {
// 		buf := make([]byte, payloadSize)
// 		if _, err := io.ReadFull(rand, buf); err != nil {
// 			b.Fatal(err)
// 		}
// 		payloads = append(payloads, buf)
// 	}

// 	b.ResetTimer()

// 	for i := 0; i < b.N; i++ {
// 		if _, err := sc.Signcrypt(source, &dest.PublicKey, []byte(plaintext), []byte(additionalData)); err != nil {
// 			b.Fatal(err)
// 		}
// 	}
// }
