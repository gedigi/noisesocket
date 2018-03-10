package main

import (
	"crypto/rand"
	"log"
	"time"

	"github.com/gedigi/noise"
	"github.com/gedigi/noisesocket"
)

func main() {
	var ncClient, ncServer noisesocket.ConnectionConfig

	cs := noise.NewCipherSuite(
		noise.DH25519,
		noise.CipherAESGCM,
		noise.HashSHA256,
	)

	clientKey, _ := cs.GenerateKeypair(rand.Reader)
	serverKey, _ := cs.GenerateKeypair(rand.Reader)

	ncClient = noisesocket.ConnectionConfig{
		IsClient:      true,
		StaticKeypair: clientKey,
		DHFunc:        noisesocket.NOISE_DH_CURVE25519,
		CipherFunc:    noisesocket.NOISE_CIPHER_AESGCM,
		HashFunc:      noisesocket.NOISE_HASH_SHA256,
	}
	ncServer = noisesocket.ConnectionConfig{
		IsClient:      false,
		DHFunc:        noisesocket.NOISE_DH_CURVE25519,
		StaticKeypair: serverKey,
	}

	// Server
	go startServer(&ncServer)
	time.Sleep(2 * time.Second)

	// Client
	log.Print("Starting client")
	conn, err := noisesocket.Dial("127.0.0.1:12345", ":0", &ncClient)
	if err != nil {
		log.Print(err)
	}
	n, err := conn.Write([]byte("hello"))
	log.Printf("writing %d %s\n", n, err)
	time.Sleep(2 * time.Second)
	// conn.Close()
	for {
	}
}

func startServer(conf *noisesocket.ConnectionConfig) {
	log.Print("Starting server")
	dialer, err := noisesocket.Listen("127.0.0.1:12345", conf)
	if err != nil {
		log.Print(err)
	}
	conn, err := dialer.Accept()
	if err != nil {
		log.Print(err)
	}
	var msg []byte
	n, err := conn.Read(msg)
	log.Printf("reading %d %s\n", n, err)
	// conn.Close()
}
