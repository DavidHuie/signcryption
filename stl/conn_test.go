package stl

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"io"
	"math/rand"
	"net"
	"sync"
	"testing"

	"github.com/DavidHuie/signcryption"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

func getClientServer(t testing.TB, r io.Reader) (*Conn, *Conn, func()) {
	clientID := getRandBytes(r, 16)
	clientPriv, err := ecdsa.GenerateKey(elliptic.P256(), r)
	if err != nil {
		t.Fatal(err)
	}
	serverID := getRandBytes(r, 16)
	serverPriv, err := ecdsa.GenerateKey(elliptic.P256(), r)
	if err != nil {
		t.Fatal(err)
	}
	tunnelID := getRandBytes(r, 16)
	tunnelPriv, err := ecdsa.GenerateKey(elliptic.P256(), r)
	if err != nil {
		t.Fatal(err)
	}

	verifier := &sessionVerifierImpl{
		clientID:     clientID,
		clientPub:    ecies.ImportECDSAPublic(&clientPriv.PublicKey),
		clientEncPub: &clientPriv.PublicKey,
		tunnelID:     tunnelID,
		tunnelPub:    ecies.ImportECDSAPublic(&tunnelPriv.PublicKey),
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
			ID:                   serverID,
			SignaturePrivateKey:  serverPriv,
			EncryptionPrivateKey: signcryption.PrivateKeyFromECDSA(serverPriv, serverID),
			SessionVerifier:      verifier,
		})
		if err := serverConn.Handshake(); err != nil {
			t.Error(err)
		}
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	clientConn := NewConn(conn, &ClientConfig{
		ClientID:                  clientID,
		HandshakePrivateKey:       ecies.ImportECDSA(clientPriv),
		ServerHandshakePublicKey:  &serverPriv.PublicKey,
		ServerID:                  serverID,
		ServerEncryptionPublicKey: signcryption.PublicKeyFromECDSA(&serverPriv.PublicKey, serverID),
		TunnelEncryptionPublicKey: &tunnelPriv.PublicKey,
		TunnelID:                  tunnelID,
		EncryptionPrivateKey:      signcryption.PrivateKeyFromECDSA(clientPriv, clientID),
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
