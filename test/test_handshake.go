package main

import (
	"crypto/rand"
	"encoding/binary"
	"log"

	"github.com/gedigi/noise"
	"github.com/gedigi/noisesocket"
	proto "github.com/golang/protobuf/proto"
)

func main() {

	var initString = []byte("NLS(revision1)")

	negotiationDataNLS := &noisesocket.NoiseLinkNegotiationDataRequest1{}
	negotiationDataNLS.ServerName = "127.0.0.1"
	negotiationDataNLS.InitialProtocol = "Noise_XX_25519_AESGCM_SHA256"
	negotiationDataNLS.SwitchProtocol = []string{"Noise_XX_25519_ChaChaPoly_SHA256"}
	negotiationDataNLS.RetryProtocol = []string{
		"Noise_XXfallback_25519_AESGCM_SHA256",
		"Noise_XXfallback_25519_ChaChaPoly_SHA256",
	}
	negData, err := proto.Marshal(negotiationDataNLS)
	if err != nil {
		log.Print(err)
	}

	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256)

	staticI, _ := cs.GenerateKeypair(rand.Reader)
	staticR, _ := cs.GenerateKeypair(rand.Reader)

	prologue := make([]byte, 2, 2+len(negData))
	binary.BigEndian.PutUint16(prologue, uint16(len(negData)))
	prologue = append(prologue, negData...)
	prologue = append(initString, prologue...)
	log.Printf("--%0s", prologue)

	hsI, err := noise.NewHandshakeState(noise.Config{
		StaticKeypair: staticI,
		Initiator:     true,
		Pattern:       noise.HandshakeXX,
		CipherSuite:   cs,
		Prologue:      prologue,
		Random:        rand.Reader,
	})

	hsR, _ := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cs,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeXX,
		StaticKeypair: staticR,
	})

	msg, _, _, _ := hsI.WriteMessage(nil, []byte("abc"))
	log.Printf("%s", msg)
	res, _, _, err := hsR.ReadMessage(nil, msg)
	log.Printf("%v", res)

	msg, _, _, _ = hsR.WriteMessage(nil, []byte("defg"))
	res, _, _, err = hsI.ReadMessage(nil, msg)
	log.Printf("%s", res)

	msg, c1, c2, _ := hsI.WriteMessage(nil, nil)
	res, c3, c4, err := hsR.ReadMessage(nil, msg)
	log.Printf("%s", c1 != nil)
	log.Printf("%s", c2 != nil)
	log.Printf("%s", c3 != nil)
	log.Printf("%s", c4 != nil)
}
