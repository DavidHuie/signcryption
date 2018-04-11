package stl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"io"
	"math/big"

	"bytes"

	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/pkg/errors"
)

// This file implements the AKE1(1) session key protocol to generate a
// shared session key between a client and a server. In this case,
// however, the session key is used as a public channel binding. The
// implementation uses ECIES for public key encryption and ECDSA for
// signatures.
//
// (1) A Graduate Course in Applied Cryptography by Boneh & Shoup

const (
	handshakeChallengeSize = 32
	sessionKeySize         = 32
)

type clientHandshaker struct {
	rand       io.Reader
	id         []byte
	priv       *ecies.PrivateKey
	dest       *ecdsa.PublicKey
	destID     []byte
	challenge  []byte
	sessionKey []byte
}

type handshakeRequest struct {
	Challenge []byte
	ID        []byte
	Pub       []byte
}

func (c *clientHandshaker) generateRequest() *handshakeRequest {
	c.challenge = getRandBytes(c.rand, handshakeChallengeSize)
	edsaPub := c.priv.PublicKey.ExportECDSA()

	return &handshakeRequest{
		Challenge: c.challenge,
		ID:        c.id,
		Pub:       elliptic.Marshal(edsaPub.Curve, edsaPub.X, edsaPub.Y),
	}
}

func (c *clientHandshaker) processServerResponse(resp *handshakeResponse) (bool, error) {
	x, y := elliptic.Unmarshal(c.priv.Curve, resp.Pub)
	pub := &ecdsa.PublicKey{
		Curve: c.priv.Curve,
		X:     x,
		Y:     y,
	}

	// Validate certificate
	if pub.X.Cmp(c.dest.X) != 0 ||
		pub.Y.Cmp(c.dest.Y) != 0 ||
		c.priv.Curve.Params().Name != pub.Curve.Params().Name ||
		bytes.Compare(resp.ID, c.destID) != 0 {
		return false, nil
	}

	// Validate signature
	sigSize := len(c.challenge) + len(resp.EncryptedSessionKey) + len(c.id)
	sigData := make([]byte, sigSize)
	copy(sigData, c.challenge)
	copy(sigData[len(resp.EncryptedSessionKey):], resp.EncryptedSessionKey)
	copy(sigData[len(c.id):], c.id)
	sigHash := sha256.New()
	sigHash.Write(sigData)

	validSig := ecdsa.Verify(
		pub,
		sigHash.Sum(nil),
		new(big.Int).SetBytes(resp.SigR),
		new(big.Int).SetBytes(resp.SigS),
	)
	if !validSig {
		return false, nil
	}

	// Decrypt session key
	sessionKeyAndID, err := c.priv.Decrypt(resp.EncryptedSessionKey, nil, nil)
	if err == ecies.ErrInvalidMessage {
		return false, nil
	}
	encryptedID := sessionKeyAndID[sessionKeySize:]
	if !bytes.Equal(encryptedID, c.destID) {
		return false, nil
	}

	c.sessionKey = sessionKeyAndID[:sessionKeySize]

	return true, nil
}

type IDVerifier interface {
	VerifyID([]byte, *ecies.PublicKey) (bool, error)
}

type serverHandshaker struct {
	rand       io.Reader
	id         []byte
	priv       *ecdsa.PrivateKey
	idVerifier IDVerifier
	sessionKey []byte
}

type handshakeResponse struct {
	EncryptedSessionKey []byte
	SigR                []byte
	SigS                []byte
	Pub                 []byte
	ID                  []byte
}

func (s *serverHandshaker) processRequest(req *handshakeRequest) (*handshakeResponse, bool, error) {
	x, y := elliptic.Unmarshal(s.priv.Curve, req.Pub)
	pub := ecies.ImportECDSAPublic(&ecdsa.PublicKey{
		Curve: s.priv.Curve,
		X:     x,
		Y:     y,
	})

	// verify the ID of the client
	valid, err := s.idVerifier.VerifyID(req.ID, pub)
	if err != nil {
		return nil, false, errors.Wrapf(err, "error validating client ID")
	}
	if !valid {
		return nil, false, nil
	}

	response := &handshakeResponse{}

	// generate and encrypt session key
	plaintext := make([]byte, handshakeChallengeSize+len(s.id))
	sessionKey := getRandBytes(s.rand, sessionKeySize)
	copy(plaintext, sessionKey)
	copy(plaintext[sessionKeySize:], s.id)

	response.EncryptedSessionKey, err = ecies.Encrypt(s.rand, pub, plaintext, nil, nil)
	if err != nil {
		return nil, false, errors.Wrapf(err, "error encrypting handshake session key")
	}

	// create signature
	sigSize := len(req.Challenge) + len(response.EncryptedSessionKey) + len(req.ID)
	sigData := make([]byte, sigSize)
	copy(sigData, req.Challenge)
	copy(sigData[len(response.EncryptedSessionKey):], response.EncryptedSessionKey)
	copy(sigData[len(req.ID):], req.ID)
	sigHash := sha256.New()
	sigHash.Write(sigData)

	sigR, sigS, err := ecdsa.Sign(s.rand, s.priv, sigHash.Sum(nil))
	if err != nil {
		return nil, false, errors.Wrapf(err, "error signing server handshake payload")
	}

	response.SigR = sigR.Bytes()
	response.SigS = sigS.Bytes()
	response.ID = s.id
	response.Pub = elliptic.Marshal(s.priv.Curve, s.priv.PublicKey.X, s.priv.PublicKey.Y)

	s.sessionKey = sessionKey

	return response, true, nil
}
