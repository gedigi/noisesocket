package noisesocket

import (
	"encoding/binary"

	"crypto/rand"

	"bytes"
	"io"

	"github.com/gedigi/noise"
	proto "github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
)

var negotiationData []byte

// var initString = []byte("NoiseSocketInit1")

func init() {
	negotiationData = make([]byte, 6)
	binary.BigEndian.PutUint16(negotiationData, 1) //version
}

// ComposeInitiatorHandshakeMessage generates handshakeState and the first noise message.
func ComposeInitiatorHandshakeMessage(s ConnectionConfig, rs []byte, payload []byte, ePrivate []byte) (negData, msg []byte, state *noise.HandshakeState, err error) {

	if len(rs) != 0 && len(rs) != dhs[s.DHFunc].DHLen() {
		return nil, nil, nil, errors.New("only 32 byte curve25519 public keys are supported")
	}
	var initString = []byte("NLS(revision1)")

	negotiationDataNLS := &NoiseLinkNegotiationDataRequest1{}
	negotiationDataNLS.ServerName = "127.0.0.1"
	if len(rs) == 0 {
		negotiationDataNLS.InitialProtocol = "Noise_XX_25519_AESGCM_SHA256"
		negotiationDataNLS.SwitchProtocol = []string{"Noise_XX_25519_ChaChaPoly_SHA256"}
	} else {
		negotiationDataNLS.InitialProtocol = "Noise_IK_25519_AESGCM_SHA256"
		negotiationDataNLS.SwitchProtocol = []string{
			"Noise_XX_25519_AESGCM_SHA256",
			"Noise_XX_25519_ChaChaPoly_SHA256",
		}
	}

	negData, err = proto.Marshal(negotiationDataNLS)
	if err != nil {
		return nil, nil, nil, errors.New("Invalid negotiation data")
	}

	var random io.Reader
	if len(ePrivate) == 0 {
		random = rand.Reader
	} else {
		random = bytes.NewBuffer(ePrivate)
	}

	prologue := make([]byte, 2, uint16Size+len(negData))
	binary.BigEndian.PutUint16(prologue, uint16(len(negData)))
	prologue = append(prologue, negData...)
	prologue = append(initString, prologue...)
	state, err = noise.NewHandshakeState(noise.Config{
		StaticKeypair: s.StaticKeypair,
		Initiator:     true,
		Pattern:       noise.HandshakeXX,
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256),
		PeerStatic:    rs,
		Prologue:      prologue,
		Random:        random,
	})

	if err != nil {
		return
	}

	msg, _, _, err = state.WriteMessage(msg, payload)

	return
}

func ParseNegotiationData(data []byte, s ConnectionConfig) (state *noise.HandshakeState, err error) {
	var initString = []byte("NLS(revision1)")

	negotiationData := &NoiseLinkNegotiationDataRequest1{}
	if err := proto.Unmarshal(data, negotiationData); err != nil {
		return nil, errors.New("Invalid negotiation data")
	}

	var protocolName string
	if _, ok := supportedProtocols[negotiationData.InitialProtocol]; !ok {
		for _, pName := range negotiationData.SwitchProtocol {
			if _, ok := supportedProtocols[pName]; ok {
				protocolName = pName
				goto success
			}
		}
		return nil, errors.New("Protocol not supported")
	}
	protocolName = negotiationData.InitialProtocol
success:
	// data = nil
	pattern, dh, cipher, hash, err := parseProtocolName(protocolName)
	prologue := make([]byte, 2, uint16Size+len(data))
	binary.BigEndian.PutUint16(prologue, uint16(len(data)))
	prologue = append(prologue, data...)
	prologue = append(initString, prologue...)
	state, err = noise.NewHandshakeState(noise.Config{
		StaticKeypair: s.StaticKeypair,
		Pattern:       patternByteObj[pattern],
		CipherSuite: noise.NewCipherSuite(
			dhByteObj[dh],
			cipherByteObj[cipher],
			hashByteObj[hash],
		),
		Prologue: prologue,
	})
	return
}
