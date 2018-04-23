package stl

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"sync"

	"github.com/DavidHuie/signcryption"
	"github.com/DavidHuie/signcryption/aal"
	"github.com/pkg/errors"
)

// ServerConnFetcher can fetch a server connection based on the client
// topic and the server certificate.
type ServerConnFetcher interface {
	GetConn(topic []byte, serverCert *signcryption.Certificate) (net.Conn, error)
}

// SegmentProcessor processes a segment. This should be used for doing
// out of band things that depend on tracking the information in each
// segment.
type SegmentProcessor interface {
	ProcessSegment(sender, reciever *signcryption.Certificate,
		segment []byte, totalBytes uint64)
}

// RelayerConfig represents configuration for a Relayer.
type RelayerConfig struct {
	Verifier    SessionVerifier
	ConnFetcher ServerConnFetcher
	RelayerCert *signcryption.Certificate
	Signcrypter aal.AAL
	Processor   SegmentProcessor
}

// Relayer stands in between a client/server connection. A client
// connection connects directly to a relayer and is then matched with
// the appropriate server connection. A Relayer can provide NAT
// traversal, firewalling, and other services at this layer.
type Relayer struct {
	sync.Mutex
	client net.Conn
	config *RelayerConfig

	// Dynamic fields
	closed                         bool
	server                         net.Conn
	clientSegments, serverSegments uint64
	clientBytes, serverBytes       uint64
	sessionKey                     []byte
	clientCert                     *signcryption.Certificate
	serverCert                     *signcryption.Certificate
}

// NewRelayer instantiates a new Relayer.
func NewRelayer(client net.Conn, config *RelayerConfig) *Relayer {
	return &Relayer{
		client: client,
		config: config,
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

	relayerCert, err := signcryption.UnmarshalCertificate(req.RelayerCert)
	if err != nil {
		return false, errors.Wrapf(err, "error unmarshaling relayer cert")
	}
	if !relayerCert.Equal(r.config.RelayerCert) {
		return false, nil
	}

	return r.config.Verifier.VerifySession(req.Topic, r.clientCert,
		r.serverCert, r.config.RelayerCert)
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
	r.server, err = r.config.ConnFetcher.GetConn(request.Topic, r.serverCert)
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

	// Decrypt session key for relayer
	var validKey bool
	r.sessionKey, validKey, err = getSessionKey(
		response.EncryptedSessionKeyForRelayer,
		r.config.RelayerCert.HandshakePrivateKey,
		r.serverCert,
	)
	if err != nil {
		return false, errors.Wrapf(err, "error decrypting session key")
	}
	if !validKey {
		return false, nil
	}

	// Send response to client
	if err := writeHandshakeResponse(r.client, response); err != nil {
		return false, errors.Wrapf(err, "error writing handshake response to client")
	}

	return true, nil
}

func (r *Relayer) processSegment(reader io.Reader, writer io.Writer,
	senderCert, recipientCert *signcryption.Certificate,
	processor SegmentProcessor, counter, bytesProcessed *uint64) (bool, error) {
	segment, segmentBytes, err := readSegment(reader)
	if err != nil {
		return false, errors.Wrapf(err, "error reading segment from reader")
	}

	// validate segment
	additionalData := make([]byte, sessionKeySize+8+8)
	copy(additionalData, r.sessionKey)
	binary.LittleEndian.PutUint64(additionalData[len(r.sessionKey):], *counter)
	binary.LittleEndian.PutUint64(additionalData[len(r.sessionKey)+8:], *bytesProcessed)

	valid, err := r.config.Signcrypter.Verify(senderCert, recipientCert,
		additionalData, segment)
	if err != nil {
		return false, errors.Wrapf(err, "error verifying segment")
	}
	if !valid {
		return false, nil
	}

	// relay data
	written, err := writer.Write(segmentBytes)
	if err != nil {
		return false, errors.Wrapf(err, "error relaying segment onto writer")
	}

	*counter++
	*bytesProcessed += uint64(written)

	if processor != nil {
		go processor.ProcessSegment(senderCert, recipientCert,
			segmentBytes, *bytesProcessed)
	}

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
				r.serverCert, r.config.Processor, &r.clientSegments,
				&r.clientBytes)
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
				r.clientCert, r.config.Processor, &r.serverSegments,
				&r.serverBytes)
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
