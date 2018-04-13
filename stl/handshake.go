package stl

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"io"
	"math/big"

	"github.com/DavidHuie/signcryption"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/pkg/errors"
)

// SessionVerifier ensures that the STL session should exist for the
// given parties.
type SessionVerifier interface {
	VerifySession(clientCert, serverCert, tunnelCert *signcryption.Certificate) (bool, error)
}

// This file implements a modified version of the AKE1(1) session key
// protocol to generate a shared session key between a client, tunnel,
// and server. The implementation uses ECIES for public key encryption
// and ECDSA for signatures.
//
// (1) A Graduate Course in Applied Cryptography by Boneh & Shoup

const (
	handshakeChallengeSize = 32
	sessionKeySize         = 32
)

type clientHandshaker struct {
	rand       io.Reader
	clientCert *signcryption.Certificate
	serverCert *signcryption.Certificate
	tunnelCert *signcryption.Certificate
	challenge  []byte
	sessionKey []byte
}

type handshakeRequest struct {
	Challenge  []byte
	ClientCert []byte
	ServerCert []byte
	TunnelCert []byte
}

func (c *clientHandshaker) generateRequest() (*handshakeRequest, error) {
	c.challenge = getRandBytes(c.rand, handshakeChallengeSize)

	client, err := c.clientCert.Marshal()
	if err != nil {
		return nil, errors.Wrapf(err, "error marshaling client certificate")
	}
	server, err := c.serverCert.Marshal()
	if err != nil {
		return nil, errors.Wrapf(err, "error marshaling server certificate")
	}
	tunnel, err := c.tunnelCert.Marshal()
	if err != nil {
		return nil, errors.Wrapf(err, "error marshaling tunnel certificate")
	}

	return &handshakeRequest{
		Challenge:  c.challenge,
		ClientCert: client,
		ServerCert: server,
		TunnelCert: tunnel,
	}, nil
}

func (c *clientHandshaker) processServerResponse(resp *handshakeResponse) (bool, error) {
	serverCert, err := signcryption.UnmarshalCertificate(resp.ServerCertificate)
	if err != nil {
		return false, errors.Wrapf(err, "error unmarshaling server cert")
	}
	if !serverCert.Equal(c.serverCert) {
		return false, nil
	}

	// Validate signature
	sigSize := len(c.challenge) + len(resp.EncryptedSessionKey) + len(c.clientCert.ID)
	sigData := make([]byte, sigSize)
	copy(sigData, c.challenge)
	copy(sigData[len(resp.EncryptedSessionKey):], resp.EncryptedSessionKey)
	copy(sigData[len(c.clientCert.ID):], c.clientCert.ID)
	sigHash := sha256.New()
	sigHash.Write(sigData)

	validSig := ecdsa.Verify(
		c.serverCert.HandshakePublicKey,
		sigHash.Sum(nil),
		new(big.Int).SetBytes(resp.SigR),
		new(big.Int).SetBytes(resp.SigS),
	)
	if !validSig {
		return false, nil
	}

	// Decrypt session key
	sessionKeyAndID, err := ecies.ImportECDSA(c.clientCert.HandshakePrivateKey).
		Decrypt(resp.EncryptedSessionKey, nil, nil)
	if err == ecies.ErrInvalidMessage {
		return false, nil
	}
	encryptedID := sessionKeyAndID[sessionKeySize:]
	if !bytes.Equal(encryptedID, c.serverCert.ID) {
		return false, nil
	}

	c.sessionKey = sessionKeyAndID[:sessionKeySize]

	return true, nil
}

type serverHandshaker struct {
	rand            io.Reader
	serverCert      *signcryption.Certificate
	sessionVerifier SessionVerifier
	sessionKey      []byte
}

type handshakeResponse struct {
	EncryptedSessionKey          []byte
	EncryptedSessionKeyForTunnel []byte
	SigR                         []byte
	SigS                         []byte
	ServerCertificate            []byte

	// This is used internally by connections
	clientCertificate *signcryption.Certificate
}

func (s *serverHandshaker) processRequest(req *handshakeRequest) (*handshakeResponse, bool, error) {
	clientCert, err := signcryption.UnmarshalCertificate(req.ClientCert)
	if err != nil {
		return nil, false, errors.Wrapf(err, "error unmarshaling client cert")
	}
	serverCert, err := signcryption.UnmarshalCertificate(req.ServerCert)
	if err != nil {
		return nil, false, errors.Wrapf(err, "error unmarshaling server cert")
	}
	var tunnelCert *signcryption.Certificate
	if len(req.TunnelCert) > 0 {
		tunnelCert, err = signcryption.UnmarshalCertificate(req.TunnelCert)
		if err != nil {
			return nil, false, errors.Wrapf(err, "error unmarshaling tunnel cert")
		}
	}

	// check that the server cert is correct
	if !serverCert.Equal(s.serverCert) {
		return nil, false, nil
	}

	// verify the session is valid
	valid, err := s.sessionVerifier.VerifySession(clientCert, serverCert, tunnelCert)
	if err != nil {
		return nil, false, errors.Wrapf(err, "error verifying session")
	}
	if !valid {
		return nil, false, nil
	}

	response := &handshakeResponse{}

	// generate and encrypt session key
	plaintext := make([]byte, handshakeChallengeSize+len(s.serverCert.ID))
	sessionKey := getRandBytes(s.rand, sessionKeySize)
	copy(plaintext, sessionKey)
	copy(plaintext[sessionKeySize:], s.serverCert.ID)

	response.EncryptedSessionKey, err = ecies.Encrypt(s.rand,
		ecies.ImportECDSAPublic(clientCert.HandshakePublicKey), plaintext, nil, nil)
	if err != nil {
		return nil, false, errors.Wrapf(err, "error encrypting handshake session key for server")
	}
	if tunnelCert != nil {
		response.EncryptedSessionKeyForTunnel, err = ecies.Encrypt(s.rand,
			ecies.ImportECDSAPublic(tunnelCert.HandshakePublicKey), plaintext, nil, nil)
		if err != nil {
			return nil, false, errors.Wrapf(err, "error encrypting handshake session key for tunnel")
		}
	}

	// create signature
	sigSize := len(req.Challenge) + len(response.EncryptedSessionKey) + len(clientCert.ID)
	sigData := make([]byte, sigSize)
	copy(sigData, req.Challenge)
	copy(sigData[len(response.EncryptedSessionKey):], response.EncryptedSessionKey)
	copy(sigData[len(clientCert.ID):], clientCert.ID)
	sigHash := sha256.New()
	sigHash.Write(sigData)

	sigR, sigS, err := ecdsa.Sign(s.rand, s.serverCert.EncryptionPrivateKey, sigHash.Sum(nil))
	if err != nil {
		return nil, false, errors.Wrapf(err, "error signing server handshake payload")
	}

	response.SigR = sigR.Bytes()
	response.SigS = sigS.Bytes()
	response.ServerCertificate, err = s.serverCert.Marshal()
	if err != nil {
		return nil, false, errors.Wrapf(err, "error marshaling server cert")
	}
	response.clientCertificate = clientCert

	s.sessionKey = sessionKey

	return response, true, nil
}
