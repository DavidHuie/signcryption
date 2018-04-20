package stl

import (
	"bytes"
	"io"
	"math/rand"
	"net"
	"sync"
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

func TestRelayerBidirectionalReadWrite(t *testing.T) {
	currentRand := int64(0)
	getRand := func() *rand.Rand {
		currentRand++
		return rand.New(rand.NewSource(currentRand))
	}

	clientConn, serverConn, _, cleanup := getClientServerRelayer(t, getRand())
	defer cleanup()

	if err := clientConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := serverConn.Handshake(); err != nil {
		t.Fatal(err)
	}

	numBytes := int64(100 * 1024 * 1024)

	rand1 := make([]byte, numBytes)
	rand2 := make([]byte, numBytes)

	clientReader := &bytes.Buffer{}
	serverReader := &bytes.Buffer{}

	if _, err := io.ReadFull(getRand(), rand1); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(getRand(), rand2); err != nil {
		t.Fatal(err)
	}

	wg := &sync.WaitGroup{}
	wg.Add(4)

	go func() {
		defer wg.Done()
		n, err := io.Copy(clientConn, bytes.NewBuffer(rand1))
		if err != nil {
			t.Fatalf("copied %d bytes, error: %s", n, err)
		}
	}()

	go func() {
		defer wg.Done()
		n, err := io.Copy(serverConn, bytes.NewBuffer(rand2))
		if err != nil {
			t.Fatalf("copied %d bytes, error: %s", n, err)
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := io.CopyN(clientReader, clientConn, numBytes); err != nil {
			t.Fatal(err)
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := io.CopyN(serverReader, serverConn, numBytes); err != nil {
			t.Fatal(err)
		}
	}()

	wg.Wait()

	if bytes.Compare(clientReader.Bytes(), rand2) != 0 {
		t.Fatal("client buffers not equal")
	}
	if bytes.Compare(serverReader.Bytes(), rand1) != 0 {
		t.Fatal("server buffers not equal")
	}
}

func BenchmarkRelayerBidirectionalReadWrite(t *testing.B) {
	currentRand := int64(0)
	getRand := func() *rand.Rand {
		currentRand++
		return rand.New(rand.NewSource(currentRand))
	}

	clientConn, serverConn, _, cleanup := getClientServerRelayer(t, getRand())
	defer cleanup()

	if err := clientConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := serverConn.Handshake(); err != nil {
		t.Fatal(err)
	}

	numBytes := int64(10 * 1024 * 1024)

	rand1 := make([]byte, numBytes)
	rand2 := make([]byte, numBytes)

	clientReader := &bytes.Buffer{}
	serverReader := &bytes.Buffer{}

	if _, err := io.ReadFull(getRand(), rand1); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(getRand(), rand2); err != nil {
		t.Fatal(err)
	}

	wg := &sync.WaitGroup{}
	wg.Add(4)

	t.ResetTimer()

	go func() {
		defer wg.Done()
		n, err := io.Copy(clientConn, bytes.NewBuffer(rand1))
		if err != nil {
			t.Fatalf("copied %d bytes, error: %s", n, err)
		}
	}()

	go func() {
		defer wg.Done()
		n, err := io.Copy(serverConn, bytes.NewBuffer(rand2))
		if err != nil {
			t.Fatalf("copied %d bytes, error: %s", n, err)
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := io.CopyN(clientReader, clientConn, numBytes); err != nil {
			t.Fatal(err)
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := io.CopyN(serverReader, serverConn, numBytes); err != nil {
			t.Fatal(err)
		}
	}()

	wg.Wait()

	if bytes.Compare(clientReader.Bytes(), rand2) != 0 {
		t.Fatal("client buffers not equal")
	}
	if bytes.Compare(serverReader.Bytes(), rand1) != 0 {
		t.Fatal("server buffers not equal")
	}
}
