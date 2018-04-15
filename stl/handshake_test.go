package stl

import (
	"bytes"
	"io"
	"math/rand"
	"testing"

	"github.com/DavidHuie/signcryption"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

type sessionVerifierImpl struct {
	clientCert *signcryption.Certificate
	tunnelCert *signcryption.Certificate
	serverCert *signcryption.Certificate
}

func (i *sessionVerifierImpl) VerifySession(c, t, s *signcryption.Certificate) (bool, error) {
	return i.clientCert.Equal(c) && i.tunnelCert.Equal(t) && i.serverCert.Equal(s), nil
}

func generateCert(t *testing.T, r io.Reader) *signcryption.Certificate {
	cert, err := signcryption.GenerateCertificate(r)
	if err != nil {
		t.Fatal(err)
	}
	cert.ID = getRandBytes(r, 16)
	return cert
}

func TestEntireHandshake(t *testing.T) {
	r := rand.New(rand.NewSource(0))

	clientCert := generateCert(t, r)
	serverCert := generateCert(t, r)
	tunnelCert := generateCert(t, r)
	sessionVerifier := &sessionVerifierImpl{
		clientCert: clientCert,
		serverCert: serverCert,
		tunnelCert: tunnelCert,
	}

	clientHandshaker := &clientHandshaker{
		rand:       r,
		clientCert: clientCert,
		serverCert: serverCert,
		tunnelCert: tunnelCert,
	}

	serverHandshaker := &serverHandshaker{
		rand:            r,
		serverCert:      serverCert,
		sessionVerifier: sessionVerifier,
	}

	request, err := clientHandshaker.generateRequest()
	if err != nil {
		t.Fatal(err)
	}

	response, valid, err := serverHandshaker.processRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("response must be valid")
	}

	valid, err = clientHandshaker.processServerResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("response not processed correctly")
	}

	tunnelSessionKey, err := ecies.ImportECDSA(tunnelCert.HandshakePrivateKey).Decrypt(response.EncryptedSessionKeyForTunnel, nil, nil)
	if err != nil {
		t.Fatalf("tunnel session key not decrypted correctly: %s", err)
	}
	tunnelSessionKey = tunnelSessionKey[:sessionKeySize]

	if !bytes.Equal(clientHandshaker.sessionKey, serverHandshaker.sessionKey) ||
		!bytes.Equal(clientHandshaker.sessionKey, tunnelSessionKey) {
		t.Fatal("session keys must match")
	}
}
