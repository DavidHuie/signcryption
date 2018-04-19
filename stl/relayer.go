package stl

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"

	"log"

	"github.com/DavidHuie/signcryption"
	"github.com/DavidHuie/signcryption/aal"
	"github.com/pkg/errors"
)

type ServerConnFetcher interface {
	GetConn(topic []byte, cert *signcryption.Certificate) (net.Conn, error)
}

type SegmentProcessor interface {
	ProcessSegment(*aal.SigncryptionOutput)
}

type Relayer struct {
	sync.Mutex
	closed                         bool
	client                         net.Conn
	server                         net.Conn
	verifier                       SessionVerifier
	connFetcher                    ServerConnFetcher
	clientCert                     *signcryption.Certificate
	serverCert                     *signcryption.Certificate
	relayerCert                    *signcryption.Certificate
	sessionKey                     []byte
	signcrypter                    aal.AAL
	clientSegments, serverSegments uint64
	processor                      SegmentProcessor
}

func NewRelayer(client net.Conn, relayerCert *signcryption.Certificate,
	signcrypter aal.AAL, processor SegmentProcessor) *Relayer {
	return &Relayer{
		client:      client,
		relayerCert: relayerCert,
		signcrypter: signcrypter,
		processor:   processor,
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

func (r *Relayer) processSegment(reader io.Reader, writer io.Writer,
	senderCert, recipientCert *signcryption.Certificate,
	processor SegmentProcessor, counter *uint64) (bool, error) {
	segment, segmentBytes, err := readSegment(reader)
	if err != nil {
		return false, errors.Wrapf(err, "error reading segment from reader")
	}

	// validate segment
	additionalData := make([]byte, sessionKeySize+8)
	copy(additionalData, r.sessionKey)
	binary.LittleEndian.PutUint64(additionalData[len(r.sessionKey):], *counter)

	valid, err := r.signcrypter.Verify(senderCert, recipientCert,
		additionalData, segment)
	if err != nil {
		return false, errors.Wrapf(err, "error verifying segment")
	}
	if !valid {
		return false, nil
	}

	// inform processors
	// TODO: maybe do this async?
	if processor != nil {
		processor.ProcessSegment(segment)
	}

	// relay data
	if _, err := io.Copy(writer, bytes.NewBuffer(segmentBytes)); err != nil {
		return false, errors.Wrapf(err, "error relaying segment onto writer")
	}

	*counter++

	return true, nil
}

func (r *Relayer) Close() {
	r.Lock()
	defer r.Unlock()

	if r.closed {
		return
	}

	r.client.Close()
	r.server.Close()
	r.closed = true
}

func (r *Relayer) Start() error {
	valid, err := r.processHandshake()
	if err != nil {
		return errors.Wrapf(err, "error processing handshake")
	}
	if !valid {
		return errors.New("validation error while processing handshake")
	}

	go func() {
		for {
			if r.closed {
				return
			}

			valid, err := r.processSegment(r.client, r.server, r.clientCert,
				r.serverCert, r.processor, &r.clientSegments)
			if err != nil {
				log.Printf("error processing segment: %s", err)
				break
			}
			if !valid {
				log.Printf("invalid segment detected")
				break
			}
		}

		r.Close()
	}()

	go func() {
		for {
			if r.closed {
				return
			}

			valid, err := r.processSegment(r.server, r.client, r.serverCert,
				r.clientCert, r.processor, &r.serverSegments)
			if err != nil {
				log.Printf("error processing segment: %s", err)
				break
			}
			if !valid {
				log.Printf("invalid segment detected")
				break
			}
		}

		r.Close()
	}()

	return nil
}
