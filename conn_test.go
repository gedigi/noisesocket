package noisesocket

import (
	"crypto/rand"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/flynn/noise"
)

func TestSwitch(t *testing.T) {
	var ncClient, ncServer ConnectionConfig

	clientKey, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	serverKey, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	log.Printf("Client Keypair: %+v", clientKey)
	log.Printf("Server Keypair: %+v", serverKey)

	ncClient = ConnectionConfig{
		StaticKeypair:   clientKey,
		PeerStatic:      clientKey.Public,
		InitialProtocol: "Noise_IK_25519_AESGCM_SHA256",
		SwitchProtocols: []string{"Noise_XXfallback_25519_AESGCM_SHA256"},
	}
	ncServer = ConnectionConfig{
		StaticKeypair: serverKey,
	}

	serverChan := make(chan string)
	// Server
	go startServer(&ncServer, &serverChan, "12345")
	time.Sleep(2 * time.Second)

	go startClient(&ncClient, &serverChan, "12345")
	a := <-serverChan
	b := <-serverChan
	if a != b {
		t.Errorf("Error: %s != %s", a, b)
	}

}
func TestRetry(t *testing.T) {
	var ncClient, ncServer ConnectionConfig

	clientKey, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	serverKey, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	log.Printf("Client Keypair: %+v", clientKey)
	log.Printf("Server Keypair: %+v", serverKey)

	ncClient = ConnectionConfig{
		StaticKeypair:   clientKey,
		PeerStatic:      clientKey.Public,
		InitialProtocol: "Noise_IK_25519_AESGCM_SHA256",
		RetryProtocols:  []string{"Noise_XX_25519_AESGCM_SHA256"},
	}
	ncServer = ConnectionConfig{
		StaticKeypair: serverKey,
	}

	serverChan := make(chan string)
	// Server
	go startServer(&ncServer, &serverChan, "12346")
	time.Sleep(2 * time.Second)

	go startClient(&ncClient, &serverChan, "12346")
	a := <-serverChan
	b := <-serverChan
	if a != b {
		t.Errorf("Error: %s != %s", a, b)
	}

}
func TestReject(t *testing.T) {
	var ncClient, ncServer ConnectionConfig

	clientKey, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	serverKey, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	log.Printf("Client Keypair: %+v", clientKey)
	log.Printf("Server Keypair: %+v", serverKey)

	ncClient = ConnectionConfig{
		StaticKeypair:   clientKey,
		PeerStatic:      clientKey.Public,
		InitialProtocol: "Noise_IK_25519_AESGCM_SHA256",
	}
	ncServer = ConnectionConfig{
		StaticKeypair: serverKey,
	}

	serverChan := make(chan string)
	// Server
	go startServer(&ncServer, &serverChan, "12347")
	time.Sleep(2 * time.Second)

	go startClient(&ncClient, &serverChan, "12347")
	a := <-serverChan
	_ = <-serverChan
	if a != "Server rejected connection" {
		t.Errorf("Error: %s != \"Server rejected connection\"", a)
	}

}

func startClient(conf *ConnectionConfig, c *chan string, port string) {
	log.Print("Starting client")
	conn, err := Dial("127.0.0.1:"+port, ":0", conf)
	if err != nil {
		log.Print(err)
	}
	defer conn.Close()
	msg := []byte("hello")
	n, err := conn.Write(msg)
	if n == 5 {
		*c <- string(msg)
	} else {
		*c <- fmt.Sprintf("%s", err)
	}
}

func startServer(conf *ConnectionConfig, c *chan string, port string) {
	log.Print("Starting server")
	dialer, err := Listen("127.0.0.1:"+port, conf)
	if err != nil {
		log.Print(err)
	}
	conn, err := dialer.Accept()
	if err != nil {
		log.Print(err)
	}
	defer conn.Close()
	msg := make([]byte, 5)
	n, err := conn.Read(msg)
	if n == 5 {
		*c <- string(msg)
	} else {
		*c <- fmt.Sprintf("%s", err)
	}
}
