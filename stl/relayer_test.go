package stl

import (
	"bytes"
	"io"
	"math/rand"
	"net"
	"testing"

	"github.com/DavidHuie/signcryption"
	"github.com/DavidHuie/signcryption/aal"
	"github.com/pkg/errors"
)

type ServerConnFetcherImpl struct {
	topic []byte
	cert  *signcryption.Certificate
	addr  net.Addr
}

func (s *ServerConnFetcherImpl) GetConn(topic []byte,
	cert *signcryption.Certificate) (net.Conn, error) {
	if !bytes.Equal(topic, s.topic) || !cert.Equal(s.cert) {
		return nil, errors.New("invalid server requested")
	}

	return net.Dial("tcp", s.addr.String())
}

func getClientServerRelayer(t testing.TB, r io.Reader) (*Conn, *Conn, *Relayer, func()) {
	clientCert := generateCert(t, r)
	serverCert := generateCert(t, r)
	relayerCert := generateCert(t, r)

	verifier := &sessionVerifierImpl{
		clientCert:  clientCert,
		serverCert:  serverCert,
		relayerCert: relayerCert,
		topic:       []byte("t1"),
	}

	serverListener, err := net.Listen("tcp", ":")
	if err != nil {
		t.Fatal(err)
	}

	var serverConn Conn
	go func() {
		conn, err := serverListener.Accept()
		if err != nil {
			t.Logf("error accepting conn: %s", err)
		}

		serverConn = *NewServerConn(conn, &ServerConfig{
			ServerCertificate: serverCert,
			SessionVerifier:   verifier,
		})
		if err := serverConn.Handshake(); err != nil {
			t.Error(err)
			conn.Close()
		}
	}()

	fetcher := &ServerConnFetcherImpl{
		topic: []byte("t1"),
		cert:  serverCert,
		addr:  serverListener.Addr(),
	}

	relayerListener, err := net.Listen("tcp", ":")
	if err != nil {
		t.Fatal(err)
	}

	var relayer Relayer
	go func() {
		conn, err := relayerListener.Accept()
		if err != nil {
			t.Logf("error accepting conn: %s", err)
		}

		relayer = *NewRelayer(conn, &RelayerConfig{
			Verifier:    verifier,
			ConnFetcher: fetcher,
			RelayerCert: relayerCert,
			Signcrypter: aal.NewP256(),
		})

		if err := relayer.Start(); err != nil {
			t.Fatal(err)
		}
	}()

	conn, err := net.Dial("tcp", relayerListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	clientConn := NewConn(conn, &ClientConfig{
		Topic:              []byte("t1"),
		ClientCertificate:  clientCert,
		ServerCertificate:  serverCert,
		RelayerCeriificate: relayerCert,
	})

	return clientConn, &serverConn, &relayer, func() {
		conn.Close()
		serverListener.Close()
		relayerListener.Close()
	}
}

func TestRelayerHandshake(t *testing.T) {
	r := rand.New(rand.NewSource(0))
	clientConn, serverConn, relayer, cleanup := getClientServerRelayer(t, r)
	defer cleanup()

	if err := clientConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := serverConn.Handshake(); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(relayer.sessionKey, clientConn.sessionKey) ||
		!bytes.Equal(clientConn.sessionKey, serverConn.sessionKey) {
		t.Fatal("session keys should be equal")
	}
}
