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

// This file implements a modified version of the AKE1(1) session key
// protocol to generate a shared session key between a client,
// relayer, and server. The implementation uses ECIES for public key
// encryption and ECDSA for signatures.
//
// (1) A Graduate Course in Applied Cryptography by Boneh & Shoup

const (
	handshakeChallengeSize = 32
	sessionKeySize         = 32
)

type clientHandshaker struct {
	rand        io.Reader
	clientCert  *signcryption.Certificate
	serverCert  *signcryption.Certificate
	relayerCert *signcryption.Certificate
	topic       []byte
	challenge   []byte
	sessionKey  []byte
}

type handshakeRequest struct {
	Challenge   []byte
	ClientCert  []byte
	ServerCert  []byte
	RelayerCert []byte

	// This is metadata that can be used for routing the connection.
	Topic []byte
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
	relayer, err := c.relayerCert.Marshal()
	if err != nil {
		return nil, errors.Wrapf(err, "error marshaling relayer certificate")
	}

	return &handshakeRequest{
		Challenge:   c.challenge,
		ClientCert:  client,
		ServerCert:  server,
		RelayerCert: relayer,
		Topic:       c.topic,
	}, nil
}

func validateServerResponse(challenge []byte, resp *handshakeResponse,
	clientCert, serverCert *signcryption.Certificate) (bool, error) {
	serverCert, err := signcryption.UnmarshalCertificate(resp.ServerCertificate)
	if err != nil {
		return false, errors.Wrapf(err, "error unmarshaling server cert")
	}
	if !serverCert.Equal(serverCert) {
		return false, nil
	}

	// Validate signature
	sigSize := handshakeChallengeSize + len(resp.EncryptedSessionKey) + len(clientCert.ID)
	sigData := make([]byte, sigSize)
	copy(sigData, challenge)
	copy(sigData[len(resp.EncryptedSessionKey):], resp.EncryptedSessionKey)
	copy(sigData[len(clientCert.ID):], clientCert.ID)
	sigHash := sha256.New()
	sigHash.Write(sigData)

	validSig := ecdsa.Verify(
		serverCert.HandshakePublicKey,
		sigHash.Sum(nil),
		new(big.Int).SetBytes(resp.SigR),
		new(big.Int).SetBytes(resp.SigS),
	)

	return validSig, nil
}

func getSessionKey(ciphertext []byte, privateKey *ecdsa.PrivateKey,
	serverCert *signcryption.Certificate) ([]byte, bool, error) {
	sessionKeyAndID, err := ecies.ImportECDSA(privateKey).
		Decrypt(ciphertext, nil, nil)
	if err == ecies.ErrInvalidMessage {
		return nil, false, nil
	}
	encryptedID := sessionKeyAndID[sessionKeySize:]
	if !bytes.Equal(encryptedID, serverCert.ID) {
		return nil, false, nil
	}
	return sessionKeyAndID[:sessionKeySize], true, nil
}

func (c *clientHandshaker) processServerResponse(resp *handshakeResponse) (bool, error) {
	valid, err := validateServerResponse(c.challenge, resp, c.clientCert, c.serverCert)
	if err != nil {
		return false, errors.Wrapf(err, "error validating server response")
	}
	if !valid {
		return false, nil
	}

	// Decrypt session key
	c.sessionKey, valid, err = getSessionKey(resp.EncryptedSessionKey,
		c.clientCert.HandshakePrivateKey, c.serverCert)
	if err != nil {
		return false, errors.Wrapf(err, "error decrypting session key")
	}
	if !valid {
		return false, nil
	}

	return true, nil
}

type serverHandshaker struct {
	rand            io.Reader
	serverCert      *signcryption.Certificate
	sessionVerifier SessionVerifier
	sessionKey      []byte
}

type handshakeResponse struct {
	EncryptedSessionKey           []byte
	EncryptedSessionKeyForRelayer []byte
	SigR                          []byte
	SigS                          []byte
	ServerCertificate             []byte

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
	var relayerCert *signcryption.Certificate
	if len(req.RelayerCert) > 0 {
		relayerCert, err = signcryption.UnmarshalCertificate(req.RelayerCert)
		if err != nil {
			return nil, false, errors.Wrapf(err, "error unmarshaling relayer cert")
		}
	}

	// check that the server cert is correct
	if !serverCert.Equal(s.serverCert) {
		return nil, false, nil
	}

	// verify the session is valid
	valid, err := s.sessionVerifier.VerifySession(req.Topic, clientCert,
		relayerCert, serverCert)
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
	if relayerCert != nil {
		response.EncryptedSessionKeyForRelayer, err = ecies.Encrypt(s.rand,
			ecies.ImportECDSAPublic(relayerCert.HandshakePublicKey), plaintext, nil, nil)
		if err != nil {
			return nil, false, errors.Wrapf(err, "error encrypting handshake session key for relayer")
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

	sigR, sigS, err := ecdsa.Sign(s.rand, s.serverCert.HandshakePrivateKey, sigHash.Sum(nil))
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
