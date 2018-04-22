package stl

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/DavidHuie/signcryption"
	"github.com/DavidHuie/signcryption/aal"
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack"
)

const (
	// This is ripped stolen from the TLS code. This value should
	// reflect the encryption that's in use here and requires some
	// tuning.
	// TODO: tune
	maxPlaintext = 16384
)

// SessionVerifier ensures that the STL session should exist for the
// given parties.
type SessionVerifier interface {
	VerifySession(topic []byte, clientCert, serverCert,
		relayerCert *signcryption.Certificate) (bool, error)
}

var (
	_ net.Conn = &Conn{}
)

// ClientConfig contains configuration needed for a client connection.
type ClientConfig struct {
	Topic              []byte
	ClientCertificate  *signcryption.Certificate
	ServerCertificate  *signcryption.Certificate
	RelayerCeriificate *signcryption.Certificate
}

// ServerConfig contains configuration needed for a server connection.
type ServerConfig struct {
	ServerCertificate *signcryption.Certificate
	SessionVerifier   SessionVerifier
}

// Conn represents a connection (either a server or a client) on a
// signcrypted transport layer.
type Conn struct {
	sync.Mutex
	conn            net.Conn
	clientConfig    *ClientConfig
	serverConfig    *ServerConfig
	sessionKey      []byte
	remoteCert      *signcryption.Certificate
	localCert       *signcryption.Certificate
	aal             aal.AAL
	readBuf         *bytes.Buffer
	writtenSegments uint64
	readSegments    uint64
}

// NewConn prepares a connection for use by a client.
func NewConn(c net.Conn, config *ClientConfig) *Conn {
	return &Conn{
		conn:         c,
		clientConfig: config,
		remoteCert:   config.ServerCertificate,
		localCert:    config.ClientCertificate,
		aal:          aal.NewP256(),
		readBuf:      &bytes.Buffer{},
	}
}

// NewServerConn prepares a connection for use by a server.
func NewServerConn(c net.Conn, config *ServerConfig) *Conn {
	return &Conn{
		conn:         c,
		serverConfig: config,
		readBuf:      &bytes.Buffer{},
		localCert:    config.ServerCertificate,
		aal:          aal.NewP256(),
	}
}

// Handshake performs the handshake procedure that's needed before
// using the connection.
func (c *Conn) Handshake() error {
	c.Lock()
	defer c.Unlock()

	if len(c.sessionKey) != 0 {
		return nil
	}
	if c.clientConfig != nil {
		return c.handshakeAsClient()
	}

	return c.handshakeAsServer()
}

// Close closes the connection.
func (c *Conn) Close() error {
	return c.conn.Close()
}

// LocalAddr returns the local address of the connection.
func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the address of the remote end of the connection.
func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets the read/write deadline on the connection.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the connection.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the connection.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func readHandshakeRequest(r io.Reader) (*handshakeRequest, error) {
	requestSizeBytes := make([]byte, 8)
	if _, err := io.ReadFull(r, requestSizeBytes); err != nil {
		return nil, errors.Wrapf(err, "error reading handshake request size")
	}
	requestSize := binary.LittleEndian.Uint64(requestSizeBytes)
	requestBytes := make([]byte, requestSize)
	if _, err := io.ReadFull(r, requestBytes); err != nil {
		return nil, errors.Wrapf(err, "error reading handshake request bytes")
	}
	var request *handshakeRequest
	if err := msgpack.Unmarshal(requestBytes, &request); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling handshake request")
	}

	return request, nil
}

func writeHandshakeResponse(w io.Writer, response *handshakeResponse) error {
	responseBytes, err := msgpack.Marshal(response)
	if err != nil {
		return errors.Wrapf(err, "error marshaling handshake response")
	}
	numResponseBytes := len(responseBytes)
	responseBuf := make([]byte, 8+numResponseBytes)
	binary.LittleEndian.PutUint64(responseBuf, uint64(numResponseBytes))
	copy(responseBuf[8:], responseBytes)
	if _, err := w.Write(responseBuf); err != nil {
		return errors.Wrapf(err, "error writing handshake response")
	}
	return nil
}

func (c *Conn) handshakeAsServer() error {
	request, err := readHandshakeRequest(c.conn)
	if err != nil {
		return errors.Wrapf(err, "error reading handshake request")
	}

	// Process request
	handshaker := &serverHandshaker{
		rand:            rand.Reader,
		serverCert:      c.serverConfig.ServerCertificate,
		sessionVerifier: c.serverConfig.SessionVerifier,
	}
	response, valid, err := handshaker.processRequest(request)
	if err != nil {
		return errors.Wrapf(err, "error processing handshake request")
	}
	if !valid {
		return errors.New("error: handshake request is not valid")
	}

	if err := writeHandshakeResponse(c.conn, response); err != nil {
		return errors.Wrapf(err, "error writing handshake response")
	}

	c.remoteCert = response.clientCertificate
	c.sessionKey = handshaker.sessionKey

	return nil
}

func writeHandshakeRequest(w io.Writer, req *handshakeRequest) error {
	requestBytes, err := msgpack.Marshal(req)
	if err != nil {
		return errors.Wrapf(err, "error marshaling client handshake request")
	}
	numRequestBytes := len(requestBytes)

	handshakeBuf := make([]byte, 8+numRequestBytes)
	binary.LittleEndian.PutUint64(handshakeBuf, uint64(numRequestBytes))
	copy(handshakeBuf[8:], requestBytes)

	// Write request to connection
	if _, err := w.Write(handshakeBuf); err != nil {
		return errors.Wrapf(err, "error writing client handshake request bytes to writer")
	}

	return nil
}

func readHandshakeResponse(r io.Reader) (*handshakeResponse, error) {
	responseSizeBytes := make([]byte, 8)
	if _, err := io.ReadFull(r, responseSizeBytes); err != nil {
		return nil, errors.Wrapf(err, "error reading handshake response size")
	}
	responseSize := binary.LittleEndian.Uint64(responseSizeBytes)
	responseBytes := make([]byte, responseSize)
	if _, err := io.ReadFull(r, responseBytes); err != nil {
		return nil, errors.Wrapf(err, "error reading handshake response bytes")
	}
	var response *handshakeResponse
	if err := msgpack.Unmarshal(responseBytes, &response); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling handshake response")
	}

	return response, nil
}

func (c *Conn) handshakeAsClient() error {
	handshaker := &clientHandshaker{
		rand:        rand.Reader,
		clientCert:  c.clientConfig.ClientCertificate,
		serverCert:  c.clientConfig.ServerCertificate,
		relayerCert: c.clientConfig.RelayerCeriificate,
		topic:       c.clientConfig.Topic,
	}
	request, err := handshaker.generateRequest()
	if err != nil {
		return errors.Wrapf(err, "error generating handshake request")
	}
	if err := writeHandshakeRequest(c.conn, request); err != nil {
		return errors.Wrapf(err, "error writing handshake request")
	}

	// Read response from connection
	response, err := readHandshakeResponse(c.conn)
	if err != nil {
		return errors.Wrapf(err, "error reading handshake response")
	}

	// Validate response
	valid, err := handshaker.processServerResponse(response)
	if err != nil {
		return errors.Wrapf(err, "error processing server handshake response")
	}
	if !valid {
		return errors.New("error: invalid server response")
	}

	c.sessionKey = handshaker.sessionKey

	return nil
}

func (c *Conn) Write(b []byte) (int, error) {
	written := 0

	for i := 0; i < len(b); i += maxPlaintext {
		writeSize := len(b) - written
		if writeSize > maxPlaintext {
			writeSize = maxPlaintext
		}

		if err := c.writeSegment(b[written : written+writeSize]); err != nil {
			return written, errors.Wrapf(err, "error writing segment")
		}

		written += writeSize
	}

	return written, nil
}

func (c *Conn) writeSegment(b []byte) error {
	additionalData := make([]byte, len(c.sessionKey)+8)
	copy(additionalData, c.sessionKey)
	binary.LittleEndian.PutUint64(additionalData[len(c.sessionKey):], c.writtenSegments)

	output, err := c.aal.Signcrypt(c.localCert, c.remoteCert, b, additionalData)
	if err != nil {
		return errors.Wrapf(err, "error signcrypting segment")
	}
	outputBytes, err := msgpack.Marshal(output)
	if err != nil {
		return errors.Wrapf(err, "error marshaling write segment")
	}
	numBytes := len(outputBytes)
	numBytesBytes := make([]byte, 8)

	binary.LittleEndian.PutUint64(numBytesBytes, uint64(numBytes))

	allOutput := make([]byte, len(numBytesBytes)+len(outputBytes))
	copy(allOutput, numBytesBytes)
	copy(allOutput[len(numBytesBytes):], outputBytes)

	if _, err := c.conn.Write(allOutput); err != nil {
		return errors.Wrapf(err, "error writing segment to connection")
	}

	c.writtenSegments++

	return nil
}

func (c *Conn) Read(b []byte) (int, error) {
	if c.readBuf.Len() == 0 {
		for {
			if err := c.readSegment(); err != nil {
				return 0, errors.Wrapf(err, "error reading segment")
			}

			// TODO: perhaps read more here
			if c.readBuf.Len() >= 0 {
				break
			}
		}
	}

	return c.readBuf.Read(b)
}

func readSegment(r io.Reader) (*aal.SigncryptionOutput, []byte, error) {
	numBytesBytes := make([]byte, 8)
	if _, err := io.ReadFull(r, numBytesBytes); err != nil {
		return nil, nil, errors.Wrapf(err, "error reading segment num bytes")
	}
	numBytes := binary.LittleEndian.Uint64(numBytesBytes)

	segmentBytes := make([]byte, numBytes)
	if _, err := io.ReadFull(r, segmentBytes); err != nil {
		return nil, nil, errors.Wrapf(err, "error reading segment bytes")
	}

	var segment *aal.SigncryptionOutput
	if err := msgpack.Unmarshal(segmentBytes, &segment); err != nil {
		return nil, nil, errors.Wrapf(err, "error unmarshaling segment")
	}

	// This is used when this payload is relayed
	total := make([]byte, len(segmentBytes)+len(numBytesBytes))
	copy(total, numBytesBytes)
	copy(total[len(numBytesBytes):], segmentBytes)

	return segment, total, nil
}

func (c *Conn) readSegment() error {
	segment, _, err := readSegment(c.conn)
	if err != nil {
		return errors.Wrapf(err, "error reading segment")
	}

	// Prepare additional data
	additionalData := make([]byte, sessionKeySize+8)
	copy(additionalData, c.sessionKey)
	binary.LittleEndian.PutUint64(additionalData[len(c.sessionKey):], c.readSegments)

	pt, valid, err := c.aal.Unsigncrypt(c.remoteCert,
		c.localCert, additionalData, segment)
	if err != nil {
		return errors.Wrapf(err, "error unsigncrypting segment")
	}
	if !valid {
		return errors.Errorf("error: segment is invalid")
	}

	c.readBuf.Write(pt)
	c.readSegments++

	return nil
}
