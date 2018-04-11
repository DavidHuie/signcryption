package stl

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/rand"
	"testing"

	"github.com/ethereum/go-ethereum/crypto/ecies"
)

type idVerifier struct {
	id  []byte
	pub *ecies.PublicKey
}

func (i *idVerifier) VerifyID(id []byte, pub *ecies.PublicKey) (bool, error) {
	cpub := pub.ExportECDSA()
	return bytes.Compare(id, i.id) == 0 &&
		cpub.X.Cmp(pub.X) == 0 &&
		cpub.Y.Cmp(pub.Y) == 0, nil
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
	idVerifier := &idVerifier{
		id:  clientID,
		pub: ecies.ImportECDSAPublic(&clientPriv.PublicKey),
	}

	clientHandshaker := &clientHandshaker{
		rand:   r,
		id:     clientID,
		priv:   ecies.ImportECDSA(clientPriv),
		dest:   &serverPriv.PublicKey,
		destID: serverID,
	}

	serverHandshaker := &serverHandshaker{
		rand:       r,
		id:         serverID,
		priv:       serverPriv,
		idVerifier: idVerifier,
	}

	request := clientHandshaker.generateRequest()

	response, valid, err := serverHandshaker.processRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Error("response must be valid")
	}

	valid, err = clientHandshaker.processServerResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Error("response not processed correctly")
	}

	if !bytes.Equal(clientHandshaker.sessionKey, serverHandshaker.sessionKey) {
		t.Error("session keys must match")
	}
}
