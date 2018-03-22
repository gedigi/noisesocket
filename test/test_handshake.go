package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"time"

	"github.com/gedigi/noisesocket"
	"github.com/gedigi/noisesocket/noise"
)

func main() {
	var ncClient, ncServer noisesocket.ConnectionConfig

	clientKey, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	serverKey, _ := noise.DH25519.GenerateKeypair(rand.Reader)
	log.Printf("Client Keypair: %+v", clientKey)
	log.Printf("Server Keypair: %+v", serverKey)

	ncClient = noisesocket.ConnectionConfig{
		IsClient:      true,
		StaticKeypair: clientKey,
		PeerStatic:    clientKey.Public,
	}
	ncServer = noisesocket.ConnectionConfig{
		IsClient:      false,
		StaticKeypair: serverKey,
	}

	serverChan := make(chan string)
	// Server
	go startServer(&ncServer, &serverChan)
	time.Sleep(2 * time.Second)

	// Client
	log.Print("Starting client")
	conn, err := noisesocket.Dial("127.0.0.1:12345", ":0", &ncClient)
	if err != nil {
		log.Print(err)
	}

	msg := []byte("hello")
	n, err := conn.Write(msg)
	log.Printf("writing %d %s %s\n", n, err, msg)
	log.Printf("%s", <-serverChan)
	conn.Close()
}

func startServer(conf *noisesocket.ConnectionConfig, c *chan string) {
	log.Print("Starting server")
	dialer, err := noisesocket.Listen("127.0.0.1:12345", conf)
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
	*c <- fmt.Sprintf("reading %d %s %s\n", n, err, msg)
}
