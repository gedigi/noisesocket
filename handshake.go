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
var appPrologue = []byte("NLS(revision1)")

func init() {
	negotiationData = make([]byte, 6)
	binary.BigEndian.PutUint16(negotiationData, 1) //version
}

func ComposeFallbackHandshakeMessage(rNegData *NoiseLinkNegotiationDataResponse1, iNoiseMsg []byte, iNegData []byte, s ConnectionConfig) ([]byte, []byte, *noise.HandshakeState, error) {
	var initString []byte
	var negData []byte
	var err error
	if rNegData != nil {
		negData, err = proto.Marshal(rNegData)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	if rNegData.GetRejected() != false {
		return negData, nil, nil, nil
	}
	if rNegData.GetSwitchProtocol() != "" {
		initString = []byte("NoiseSocketInit2")
	}
	if rNegData.GetRetryProtocol() != "" {
		initString = []byte("NoiseSocketInit3")
	}

	// original negotiation data
	prologue := make([]byte, 2, uint16Size+len(iNegData))
	binary.BigEndian.PutUint16(prologue, uint16(len(iNegData)))
	prologue = append(prologue, iNegData...)

	// original noise message
	iNoiseMsgLen := make([]byte, 2, uint16Size+len(iNoiseMsg))
	binary.BigEndian.PutUint16(prologue, uint16(len(iNoiseMsg)))
	iNoiseMsg = append(iNoiseMsgLen, iNoiseMsg...)
	prologue = append(prologue, iNoiseMsg...)

	// responder negotiation data
	negDataLen := make([]byte, 2, uint16Size+len(negData))
	binary.BigEndian.PutUint16(prologue, uint16(len(negData)))
	negData = append(negDataLen, negData...)
	prologue = append(prologue, negData...)

	prologue = append(initString, prologue...)
	prologue = append(prologue, appPrologue...)

	state, err := noise.NewHandshakeState(noise.Config{
		StaticKeypair: s.StaticKeypair,
		Initiator:     true,
		Pattern:       noise.HandshakeXX,
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256),
		Prologue:      prologue,
		Random:        rand.Reader,
	})
	if err != nil {
		return nil, nil, nil, err
	}

	msg := []byte(nil)
	msg, _, _, err = state.WriteMessage(msg, nil)

	return negData, msg, state, nil

}

// ComposeInitiatorHandshakeMessage generates handshakeState and the first noise message.
func ComposeInitiatorHandshakeMessage(s ConnectionConfig, rs []byte, payload []byte, ePrivate []byte) (negData, msg []byte, state *noise.HandshakeState, err error) {

	if len(rs) != 0 && len(rs) != dhs[s.DHFunc].DHLen() {
		return nil, nil, nil, errors.New("only 32 byte curve25519 public keys are supported")
	}
	var initString = []byte("NoiseSocketInit1")

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
	prologue = append(prologue, appPrologue...)
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

func ParseNegotiationData(data []byte, s ConnectionConfig) (*NoiseLinkNegotiationDataResponse1, *noise.HandshakeState, error) {

	negotiationData := &NoiseLinkNegotiationDataRequest1{}
	if err := proto.Unmarshal(data, negotiationData); err != nil {
		return nil, nil, err
	}

	if _, ok := supportedProtocols[negotiationData.InitialProtocol]; ok {
		var initString = []byte("NoiseSocketInit1")
		pattern, dh, cipher, hash, err := parseProtocolName(negotiationData.InitialProtocol)
		if err != nil {
			return nil, nil, err
		}
		prologue := make([]byte, 2, uint16Size+len(data))
		binary.BigEndian.PutUint16(prologue, uint16(len(data)))
		prologue = append(prologue, data...)
		prologue = append(initString, prologue...)
		prologue = append(prologue, appPrologue...)
		state, err := noise.NewHandshakeState(noise.Config{
			StaticKeypair: s.StaticKeypair,
			Pattern:       patternByteObj[pattern],
			CipherSuite: noise.NewCipherSuite(
				dhByteObj[dh],
				cipherByteObj[cipher],
				hashByteObj[hash],
			),
			Prologue: prologue,
		})
		if err != nil {
			return nil, nil, err
		}
		return nil, state, nil
	}

	negotiationDataNLS := &NoiseLinkNegotiationDataResponse1{}

	for _, pName := range negotiationData.SwitchProtocol {
		if _, ok := supportedProtocols[pName]; ok {
			negotiationDataNLS.Response = &NoiseLinkNegotiationDataResponse1_SwitchProtocol{
				SwitchProtocol: pName,
			}
			goto returnFunc
		}
	}
	for _, pName := range negotiationData.RetryProtocol {
		if _, ok := supportedProtocols[pName]; ok {
			negotiationDataNLS.Response = &NoiseLinkNegotiationDataResponse1_RetryProtocol{
				RetryProtocol: pName,
			}
			goto returnFunc
		}
	}
	negotiationDataNLS.Response = &NoiseLinkNegotiationDataResponse1_Rejected{
		Rejected: true,
	}

returnFunc:
	return negotiationDataNLS, nil, nil
}
