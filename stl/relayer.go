package stl

import (
	"net"

	"github.com/DavidHuie/signcryption"
	"github.com/pkg/errors"
)

type ServerConnFetcher interface {
	GetConn(topic []byte, cert *signcryption.Certificate) (net.Conn, error)
}

type Relayer struct {
	client      net.Conn
	server      net.Conn
	verifier    SessionVerifier
	connFetcher ServerConnFetcher
	clientCert  *signcryption.Certificate
	serverCert  *signcryption.Certificate
	relayerCert *signcryption.Certificate
	sessionKey  []byte
}

func NewRelayer(client net.Conn, relayerCert *signcryption.Certificate) *Relayer {
	return &Relayer{
		client:      client,
		relayerCert: relayerCert,
	}
}

func (r *Relayer) verifyRequest(req *handshakeRequest) (bool, error) {
	var err error
	r.clientCert, err = signcryption.UnmarshalCertificate(req.ClientCert)
	if err != nil {
		return false, errors.Wrapf(err, "error unmarshaling client cert")
	}
	r.serverCert, err = signcryption.UnmarshalCertificate(req.ServerCert)
	if err != nil {
		return false, errors.Wrapf(err, "error unmarshaling server cert")
	}

	relayerCert, err := signcryption.UnmarshalCertificate(req.TunnelCert)
	if err != nil {
		return false, errors.Wrapf(err, "error unmarshaling relayer cert")
	}
	if !relayerCert.Equal(r.relayerCert) {
		return false, nil
	}

	return r.verifier.VerifySession(req.Topic, r.clientCert,
		r.serverCert, r.relayerCert)
}

func (r *Relayer) processHandshake() (bool, error) {
	// Read handshake request from client
	request, err := readHandshakeRequest(r.client)
	if err != nil {
		return false, errors.Wrapf(err, "error reading handshake request")
	}

	// Verify request
	validRequest, err := r.verifyRequest(request)
	if err != nil {
		return false, errors.Wrapf(err, "error verifying request")
	}
	if !validRequest {
		return false, nil
	}

	// Fetch server conn
	r.server, err = r.connFetcher.GetConn(request.Topic, r.serverCert)
	if err != nil {
		return false, errors.Wrapf(err, "error fetching server connection")
	}

	// Relay handshake to server
	if err := writeHandshakeRequest(r.server, request); err != nil {
		return false, errors.Wrapf(err, "error relaying handshake request to server")
	}

	// Read handshake response
	response, err := readHandshakeResponse(r.server)
	if err != nil {
		return false, errors.Wrapf(err, "error reading handshake response from server")
	}

	// Verify response
	validResponse, err := validateServerResponse(request.Challenge, response,
		r.clientCert, r.serverCert)
	if err != nil {
		return false, errors.Wrapf(err, "error validating server response")
	}
	if !validResponse {
		return false, nil
	}

	// Decrypt session key for tunnel
	var validKey bool
	r.sessionKey, validKey, err = getSessionKey(response.EncryptedSessionKeyForTunnel,
		r.relayerCert.HandshakePrivateKey, r.serverCert)
	if err != nil {
		return false, errors.Wrapf(err, "error decrypting session key")
	}
	if !validKey {
		return false, nil
	}

	return true, nil
}
