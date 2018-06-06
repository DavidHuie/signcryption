package aai

import (
	"encoding/base64"
	"io"
	"math/rand"
	"testing"

	"github.com/DavidHuie/signcryption"
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

func genCert(t testing.TB, rand io.Reader) *signcryption.Certificate {
	cert, err := signcryption.GenerateCertificate(rand)
	if err != nil {
		t.Fatal(err)
	}

	cert.ID = make([]byte, 16)
	if _, err := io.ReadFull(rand, cert.ID); err != nil {
		t.Fatal(err)
	}

	return cert
}

func TestP256Signcrypt(t *testing.T) {
	rand := rand.New(rand.NewSource(0))

	sc := newP256(rand)
	source, dest := genCert(t, rand), genCert(t, rand)

	output, err := sc.Signcrypt(source, dest, []byte(plaintext), []byte(additionalData))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("should encrypt correctly", func(t *testing.T) {
		if toBase64(output.Ciphertext) != `7OC4t8GWXZGBJRt8nJylIJtkadNss3rVM3Koo4PE1rKNA309FnOZ+V8xdph9zGZ4U/QLCjL2D3EhLEd2AhS9Me7DmG7dfKY8ZpjswKp83M7VKjojWvyvfgF3Zd39Lhi48JjY6CG7zouktn4bB91pKoWFhJWYOJWdM0iLKo0+JPKXWXnx9TtLREprjY1+YVPWKLBEzw7XnqIQG6W1gaiFEIH6IeBa5BDlg0xRr5VQBJgPS65B+vl3OvC0zSlvdEg3rFMcHgg2GPn8sLCE5szq+8xcqdTMUEtpSIzja01cmp2V3q51WCQ=` {
			t.Log(toBase64(output.Ciphertext))
			t.Error("invalid ciphertext")
		}
		if toBase64(output.R) != `BGe9fkupa02vVrdudPHrLPAOb6pST4LFAC2MZcoewOfxTtC5F+r416C6nMudGtJsj2Dtb1yHK0zqrxIkphIYt2U=` {
			t.Log(toBase64(output.R))
			t.Error("invalid r")
		}
		if toBase64(output.Signature) != `/W3BKrjDRkHwSJx57cIYNM/doTMtxQBlLc2EaHlZa1k=` {
			t.Log(toBase64(output.Signature))
			t.Error("invalid signature")
		}
	})

	t.Run("should verify", func(t *testing.T) {
		valid, err := sc.Verify(source, dest, []byte(additionalData), output)
		if err != nil {
			t.Fatal(err)
		}
		if !valid {
			t.Error("signature should be valid")
		}
	})

	t.Run("should reject bad additional data", func(t *testing.T) {
		valid, err := sc.Verify(source, dest, nil, output)
		if err != nil {
			t.Fatal(err)
		}
		if valid {
			t.Error("signature should not be valid")
		}
	})

	t.Run("should unsigncrypt", func(t *testing.T) {
		plaintextCandidate, valid, err := sc.Unsigncrypt(source, dest, []byte(additionalData), output)
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
	source, dest := genCert(b, rand), genCert(b, rand)

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
		if _, err := sc.Signcrypt(source, dest, []byte(plaintext), []byte(additionalData)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnsigncrypt256(b *testing.B) {
	rand := rand.New(rand.NewSource(0))
	sc := newP256(rand)
	source, dest := genCert(b, rand), genCert(b, rand)

	var ciphertexts []*SigncryptionOutput
	for i := 0; i < b.N; i++ {
		buf := make([]byte, payloadSize)
		if _, err := io.ReadFull(rand, buf); err != nil {
			b.Fatal(err)
		}
		ct, err := sc.Signcrypt(source, dest, []byte(plaintext), []byte(additionalData))
		if err != nil {
			b.Fatal(err)
		}
		ciphertexts = append(ciphertexts, ct)
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, ok, err := sc.Unsigncrypt(source, dest, []byte(additionalData), ciphertexts[i])
		if err != nil {
			b.Fatal(err)
		}
		if !ok {
			b.Error("not ok returned")
		}
	}
}
