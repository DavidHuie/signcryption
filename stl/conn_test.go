package stl

import (
	"bytes"
	"io"
	"math/rand"
	"net"
	"sync"
	"testing"
)

func getClientServer(t testing.TB, r io.Reader) (*Conn, *Conn, func()) {
	clientCert := generateCert(t, r)
	serverCert := generateCert(t, r)
	relayerCert := generateCert(t, r)

	verifier := &sessionVerifierImpl{
		clientCert:  clientCert,
		serverCert:  serverCert,
		relayerCert: relayerCert,
		topic:       []byte("t1"),
	}

	listener, err := net.Listen("tcp", ":")
	if err != nil {
		t.Fatal(err)
	}

	var serverConn Conn

	go func() {
		conn, err := listener.Accept()
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

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	clientConn := NewConn(conn, &ClientConfig{
		Topic:              []byte("t1"),
		ClientCertificate:  clientCert,
		ServerCertificate:  serverCert,
		RelayerCeriificate: relayerCert,
	})

	return clientConn, &serverConn, func() {
		conn.Close()
		listener.Close()
	}
}

func TestConnIntegration(t *testing.T) {
	clientConn, serverConn, cleanup := getClientServer(t, rand.New(rand.NewSource(0)))
	defer cleanup()

	if err := clientConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := serverConn.Handshake(); err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(clientConn.sessionKey, serverConn.sessionKey) != 0 {
		t.Fatal("session keys must match")
	}
}

func TestBidirectionalReadWrite(t *testing.T) {
	currentRand := int64(0)
	getRand := func() *rand.Rand {
		currentRand++
		return rand.New(rand.NewSource(currentRand))
	}

	clientConn, serverConn, cleanup := getClientServer(t, getRand())
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

func BenchmarkBidirectionalReadWrite(t *testing.B) {
	currentRand := int64(0)
	getRand := func() *rand.Rand {
		currentRand++
		return rand.New(rand.NewSource(currentRand))
	}

	clientConn, serverConn, cleanup := getClientServer(t, getRand())
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
