package noisesocket

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"log"

	"github.com/golang/protobuf/proto"

	"github.com/gedigi/noisesocket/noise"
	"github.com/pkg/errors"
)

var appPrologue = []byte("NLS(revision1)")

// ComposeInitiatorHandshakeMessage generates handshakeState and the first noise message.
func ComposeInitiatorHandshakeMessage(s ConnectionConfig) (
	negData, msg []byte,
	state *noise.HandshakeState,
	err error,
) {

	if len(s.PeerStatic) != 0 && len(s.PeerStatic) != dhs[s.DHFunc].DHLen() {
		return nil, nil, nil, errors.New("only 32 byte curve25519 public keys are supported")
	}

	var pattern noise.HandshakePattern
	var negotiationData = &NoiseLinkNegotiationDataRequest1{}
	negotiationData.ServerName = s.ServerName

	if len(s.PeerStatic) == 0 {
		pattern = noise.HandshakeXX
		negotiationData.InitialProtocol = "Noise_XX_22519_AESGCM_SHA256"
	} else {
		pattern = noise.HandshakeIK
		negotiationData.InitialProtocol = "Noise_IK_22519_AESGCM_SHA256"
	}

	negData, _ = json.Marshal(negotiationData)
	log.Printf("%s", negData)

	prologue := makePrologue([][]byte{negData}, "NoiseSocketInit1")
	state, err = noise.NewHandshakeState(noise.Config{
		StaticKeypair: s.StaticKeypair,
		Initiator:     true,
		Pattern:       pattern,
		CipherSuite:   noise.NewCipherSuite(dhs[s.DHFunc], ciphers[s.CipherFunc], hashes[s.HashFunc]),
		PeerStatic:    s.PeerStatic,
		Prologue:      prologue,
		Random:        rand.Reader,
	})

	if err != nil {
		return
	}

	msg, _, _, err = state.WriteMessage(msg, s.Payload)

	return
}

func ParseNegotiationData(data []byte, s ConnectionConfig) (state *noise.HandshakeState, err error) {

	var (
		ok                   bool
		hs, dh, cipher, hash byte
	)
	dataParsed := &NoiseLinkNegotiationDataRequest1{}
	log.Printf("%s", data)
	if err = proto.Unmarshal(data, dataParsed); err != nil {
		return nil, err
	}
	if _, ok = supportedProtocols[dataParsed.InitialProtocol]; !ok {
		return nil, errors.New("unsupported protocol")
	}

	hs, dh, cipher, hash, _, err = parseProtocolName(dataParsed.InitialProtocol)

	prologue := makePrologue([][]byte{data}, "NoiseSocketInit1")
	state, err = noise.NewHandshakeState(noise.Config{
		StaticKeypair: s.StaticKeypair,
		Pattern:       patternByteObj[hs],
		CipherSuite: noise.NewCipherSuite(
			dhByteObj[dh],
			cipherByteObj[cipher],
			hashByteObj[hash],
		),
		Prologue: prologue,
	})
	return
}

func makePrologue(dataSlice [][]byte, initString string) (output []byte) {
	output = append([]byte(initString), output...)
	for _, data := range dataSlice {
		dataLen := make([]byte, 2, uint16Size+len(data))
		binary.BigEndian.PutUint16(dataLen, uint16(len(data)))
		output = append(dataLen, data...)
	}
	output = append(output, appPrologue...)
	return
}
