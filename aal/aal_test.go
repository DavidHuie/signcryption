package aal

import (
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

func genPrivateKey(t testing.TB, rand io.Reader) *PrivateKey {
	pk, err := GeneratePrivateKey(elliptic.P256(), rand)
	if err != nil {
		t.Fatal(err)
	}

	pk.ID = make([]byte, 16)
	if _, err := io.ReadFull(rand, pk.ID); err != nil {
		t.Fatal(err)
	}

	return pk
}

func TestP256Signcrypt(t *testing.T) {
	rand := rand.New(rand.NewSource(0))

	sc := newP256(rand)
	source, dest := genPrivateKey(t, rand), genPrivateKey(t, rand)

	output, err := sc.Signcrypt(source, &dest.PublicKey, []byte(plaintext), []byte(additionalData))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("should encrypt correctly", func(t *testing.T) {
		if toBase64(output.Ciphertext) != `i8ue8tSmUxR2jW0pl2HqnrT7JVYlv6YwSz2uNCyPzTL03mm+0bGfDDKXWcJTJ+4bQtn9Q8U1WESUz/OveqovcAkK47i1HbqbuRpnylhiS1pdvhsnXNNGO6arQVor8t9h25oi5h2hy32nJrlxqV7RgY1U85nucWSUs+63QnACWAbP9xQtUZqgiiiQ+mdgByQIX/kjuIRYhGEKLH5qbn8621fyWKSpXz1Z+CF7z0m07x/M3+SDyjxD1P0oCH+Ms6BGLTEGjKQ+tQFcDHZPwBnVLTcB8GOmAw+7mOUUaMiFEGlaB/ZepSk=` {
			t.Log(toBase64(output.Ciphertext))
			t.Error("invalid ciphertext")
		}
		if toBase64(output.R) != `BPr/c0wq47ejJVxDhxehPdzq5TCPBGkapZ6lyHa5R8Dj7feDqEul06DjUUvTWx6v0+kXWobf4J4nsWj58vUAdwg=` {
			t.Log(toBase64(output.R))
			t.Error("invalid r")
		}
		if toBase64(output.Signature) != `TJ7lbRvsnrksn3STr/2+BOEhS0SCOCLoZnDuJxlQZUE=` {
			t.Log(toBase64(output.Signature))
			t.Error("invalid signature")
		}
	})

	t.Run("should verify", func(t *testing.T) {
		valid, err := sc.Verify(&source.PublicKey, &dest.PublicKey, []byte(additionalData), output)
		if err != nil {
			t.Fatal(err)
		}
		if !valid {
			t.Error("signature should be valid")
		}
	})

	t.Run("should unsigncrypt", func(t *testing.T) {
		plaintextCandidate, valid, err := sc.Unsigncrypt(&source.PublicKey, dest, []byte(additionalData), output)
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
	source, dest := genPrivateKey(b, rand), genPrivateKey(b, rand)

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
	source, dest := genPrivateKey(b, rand), genPrivateKey(b, rand)

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
		_, ok, err := sc.Unsigncrypt(&source.PublicKey, dest, []byte(additionalData), ciphertexts[i])
		if err != nil {
			b.Fatal(err)
		}
		if !ok {
			b.Error("not ok returned")
		}
	}
}
