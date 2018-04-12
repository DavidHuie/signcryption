package stl

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"io"
	"math/rand"
	"net"
	"testing"

	cryptorand "crypto/rand"

	"github.com/DavidHuie/signcryption"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

func getClientServer(t *testing.T, r io.Reader) (*Conn, *Conn, func()) {
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

	if bytes.Compare(clientConn.sessionKey, serverConn.sessionKey) != 0 {
		t.Fatal("session keys must match")
	}
}

func TestBidirectionalReadWrite(t *testing.T) {
	r := cryptorand.Reader

	clientConn, serverConn, cleanup := getClientServer(t, r)
	defer cleanup()

	if err := clientConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := serverConn.Handshake(); err != nil {
		t.Fatal(err)
	}

	clientBuf := &bytes.Buffer{}
	serverBuf := &bytes.Buffer{}

	numBytes := int64(10 * 1024 * 1024)

	go func() {
		n, err := io.CopyN(io.MultiWriter(clientConn, clientBuf), r, numBytes)
		if err != nil {
			t.Fatalf("copied %d bytes, error: %s", n, err)
		}
	}()

	go func() {
		n, err := io.CopyN(io.MultiWriter(serverConn, serverBuf), r, numBytes)
		if err != nil {
			t.Fatalf("copied %d bytes, error: %s", n, err)
		}
	}()

	clientReadBuf := make([]byte, numBytes)
	if _, err := io.ReadFull(serverConn, clientReadBuf); err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(clientReadBuf, clientBuf.Bytes()) != 0 {
		t.Fatal("client buffers not equal")
	}

	serverReadBuf := make([]byte, numBytes)
	if _, err := io.ReadFull(clientConn, serverReadBuf); err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(serverReadBuf, serverBuf.Bytes()) != 0 {
		t.Fatal("server buffers not equal")
	}
}
