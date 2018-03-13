package noisesocket

import (
	"encoding/binary"

	"crypto/rand"

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

// ComposeInitiatorHandshakeMessage generates handshakeState and the first noise message.
func InitiatorHandshake(s ConnectionConfig, n NegotiationData) (
	negData, msg []byte,
	state *noise.HandshakeState,
	err error,
) {

	if len(s.PeerStatic) != 0 && len(s.PeerStatic) != dhs[s.DHFunc].DHLen() {
		return nil, nil, nil, errors.New("only 32 byte curve25519 public keys are supported")
	}
	if n.ResponseNegData == nil {
		negotiationDataNLS := &NoiseLinkNegotiationDataRequest1{}
		negotiationDataNLS.ServerName = "127.0.0.1"
		if len(s.PeerStatic) == 0 {
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

		prologue := make([]byte, 2, uint16Size+len(negData))
		binary.BigEndian.PutUint16(prologue, uint16(len(negData)))
		prologue = append(prologue, negData...)
		prologue = append(n.InitString, prologue...)
		prologue = append(prologue, appPrologue...)
		state, err = noise.NewHandshakeState(noise.Config{
			StaticKeypair: s.StaticKeypair,
			Initiator:     true,
			Pattern:       noise.HandshakeXX,
			CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256),
			PeerStatic:    s.PeerStatic,
			Prologue:      prologue,
		})

		if err != nil {
			return
		}

		msg, _, _, err = state.WriteMessage(msg, s.Payload)

		return
	}
	if n.ResponseNegData != nil {
		negData, err = proto.Marshal(n.ResponseNegData)
		if err != nil {
			return nil, nil, nil, err
		}
	}

	if n.ResponseNegData.GetRejected() != false {
		return negData, nil, nil, nil
	}

	// original negotiation data
	prologue := make([]byte, 2, uint16Size+len(n.RemoteNegData))
	binary.BigEndian.PutUint16(prologue, uint16(len(n.RemoteNegData)))
	prologue = append(prologue, n.RemoteNegData...)

	// original noise message
	rNoiseMsgLen := make([]byte, 2, uint16Size+len(n.RemoteNoiseMsg))
	binary.BigEndian.PutUint16(rNoiseMsgLen, uint16(len(n.RemoteNoiseMsg)))
	prologue = append(prologue, rNoiseMsgLen...)
	prologue = append(prologue, n.RemoteNoiseMsg...)

	// responder negotiation data
	negDataLen := make([]byte, 2, uint16Size+len(negData))
	binary.BigEndian.PutUint16(negDataLen, uint16(len(negData)))
	prologue = append(prologue, negDataLen...)
	prologue = append(prologue, negData...)

	prologue = append(n.InitString, prologue...)
	prologue = append(prologue, appPrologue...)

	state, err = noise.NewHandshakeState(noise.Config{
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

	msg, _, _, err = state.WriteMessage(msg, s.Payload)

	return
}

func ParseNegotiationData(data []byte, s ConnectionConfig) (*NoiseLinkNegotiationDataResponse1, *noise.HandshakeState, error) {

	negotiationData := &NoiseLinkNegotiationDataRequest1{}
	if err := proto.Unmarshal(data, negotiationData); err != nil {
		return nil, nil, err
	}

	// Accept
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

	// Switch
	for _, pName := range negotiationData.SwitchProtocol {
		if _, ok := supportedProtocols[pName]; ok {
			negotiationDataNLS.Response = &NoiseLinkNegotiationDataResponse1_SwitchProtocol{
				SwitchProtocol: pName,
			}
			goto returnFunc
		}
	}

	// Retry
	for _, pName := range negotiationData.RetryProtocol {
		if _, ok := supportedProtocols[pName]; ok {
			negotiationDataNLS.Response = &NoiseLinkNegotiationDataResponse1_RetryProtocol{
				RetryProtocol: pName,
			}
			goto returnFunc
		}
	}

	// Reject
	negotiationDataNLS.Response = &NoiseLinkNegotiationDataResponse1_Rejected{
		Rejected: true,
	}

returnFunc:
	return negotiationDataNLS, nil, nil
}

// NegotiationData holds information related to the negotiation_data field
type NegotiationData struct {
	InitString      []byte
	RemoteNoiseMsg  []byte
	RemoteNegData   []byte
	ResponseNegData *NoiseLinkNegotiationDataResponse1
}
