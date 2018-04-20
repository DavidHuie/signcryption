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
	topic       []byte
	clientCert  *signcryption.Certificate
	relayerCert *signcryption.Certificate
	serverCert  *signcryption.Certificate
}

func (i *sessionVerifierImpl) VerifySession(topic []byte, c, s, t *signcryption.Certificate) (bool, error) {
	return bytes.Equal(i.topic, topic) && i.clientCert.Equal(c) &&
		i.relayerCert.Equal(t) && i.serverCert.Equal(s), nil
}

func generateCert(t testing.TB, r io.Reader) *signcryption.Certificate {
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
	relayerCert := generateCert(t, r)
	sessionVerifier := &sessionVerifierImpl{
		clientCert:  clientCert,
		serverCert:  serverCert,
		relayerCert: relayerCert,
	}

	clientHandshaker := &clientHandshaker{
		rand:        r,
		clientCert:  clientCert,
		serverCert:  serverCert,
		relayerCert: relayerCert,
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

	relayerSessionKey, err := ecies.ImportECDSA(relayerCert.HandshakePrivateKey).Decrypt(response.EncryptedSessionKeyForRelayer, nil, nil)
	if err != nil {
		t.Fatalf("relayer session key not decrypted correctly: %s", err)
	}
	relayerSessionKey = relayerSessionKey[:sessionKeySize]

	if !bytes.Equal(clientHandshaker.sessionKey, serverHandshaker.sessionKey) ||
		!bytes.Equal(clientHandshaker.sessionKey, relayerSessionKey) {
		t.Fatal("session keys must match")
	}
}
