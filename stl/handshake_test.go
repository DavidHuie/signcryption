package stl

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/rand"
	"testing"

	"github.com/ethereum/go-ethereum/crypto/ecies"
)

type sessionVerifierImpl struct {
	clientID  []byte
	clientPub *ecies.PublicKey
	tunnelID  []byte
	tunnelPub *ecies.PublicKey
}

func (s *sessionVerifierImpl) VerifySession(clientID []byte, clientPub *ecies.PublicKey,
	tunnelID []byte, tunnelPub *ecies.PublicKey) (bool, error) {
	clientEqual := bytes.Compare(clientID, s.clientID) == 0 &&
		s.clientPub.X.Cmp(clientPub.X) == 0 &&
		s.clientPub.Y.Cmp(clientPub.Y) == 0

	tunnelEqual := bytes.Compare(tunnelID, s.tunnelID) == 0 &&
		s.tunnelPub.X.Cmp(tunnelPub.X) == 0 &&
		s.tunnelPub.Y.Cmp(tunnelPub.Y) == 0

	return clientEqual && tunnelEqual, nil
}

func TestEntireHandshake(t *testing.T) {
	r := rand.New(rand.NewSource(0))
	clientID := getRandBytes(r, 16)
	clientPriv, err := ecdsa.GenerateKey(elliptic.P256(), r)
	if err != nil {
		t.Fatal(err)
	}
	serverID := getRandBytes(r, 16)
	serverPriv, err := ecdsa.GenerateKey(elliptic.P256(), r)
	if err != nil {
		t.Fatal(err)
	}
	tunnelID := getRandBytes(r, 16)
	tunnelPriv, err := ecdsa.GenerateKey(elliptic.P256(), r)
	if err != nil {
		t.Fatal(err)
	}
	sessionVerifier := &sessionVerifierImpl{
		clientID:  clientID,
		clientPub: ecies.ImportECDSAPublic(&clientPriv.PublicKey),
		tunnelID:  tunnelID,
		tunnelPub: ecies.ImportECDSAPublic(&tunnelPriv.PublicKey),
	}

	clientHandshaker := &clientHandshaker{
		rand:      r,
		id:        clientID,
		priv:      ecies.ImportECDSA(clientPriv),
		serverPub: &serverPriv.PublicKey,
		serverID:  serverID,
		tunnelPub: &tunnelPriv.PublicKey,
		tunnelID:  tunnelID,
	}

	serverHandshaker := &serverHandshaker{
		rand:            r,
		id:              serverID,
		priv:            serverPriv,
		sessionVerifier: sessionVerifier,
	}

	request := clientHandshaker.generateRequest()

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

	if !bytes.Equal(clientHandshaker.sessionKey, serverHandshaker.sessionKey) {
		t.Fatal("session keys must match")
	}
}
