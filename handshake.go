package noisesocket

import (
	"encoding/binary"

	"github.com/gedigi/noisesocket/noise"
	proto "github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
)

var negotiationData []byte
var appPrologue = []byte("NLS(revision1)")

func init() {
	negotiationData = make([]byte, 6)
	binary.BigEndian.PutUint16(negotiationData, 1) //version
}

// InitiatorHandshake generates appropriate handshakeState and noise message
func InitiatorHandshake(s ConnectionConfig, n NegotiationData) (
	negData, msg []byte,
	state *noise.HandshakeState,
	err error,
) {
	var (
		prologue []byte
		pattern  noise.HandshakePattern
	)

	if len(s.PeerStatic) != 0 && len(s.PeerStatic) != dhs[s.DHFunc].DHLen() {
		return nil, nil, nil, errors.New("only 32 byte curve25519 public keys are supported")
	}
	if n.ResponseNegData == nil {
		negotiationDataNLS := &NoiseLinkNegotiationDataRequest1{}
		negotiationDataNLS.ServerName = s.ServerHostname
		if len(s.PeerStatic) == 0 {
			negotiationDataNLS.InitialProtocol = "Noise_XX_25519_AESGCM_SHA256"
			negotiationDataNLS.SwitchProtocol = []string{"Noise_XX_25519_ChaChaPoly_SHA256"}
			pattern = noise.HandshakeXX
		} else {
			negotiationDataNLS.InitialProtocol = "Noise_IK_25519_AESGCM_SHA256"
			negotiationDataNLS.SwitchProtocol = []string{
				"Noise_XX_25519_AESGCM_SHA256",
				"Noise_XX_25519_ChaChaPoly_SHA256",
			}
			pattern = noise.HandshakeIK
		}

		negData, err = proto.Marshal(negotiationDataNLS)
		if err != nil {
			return nil, nil, nil, errors.New("Invalid negotiation data")
		}

		prologue = makePrologue([][]byte{negData}, n.InitString)
	} else {
		pattern = noise.HandshakeXX
		negData, err = proto.Marshal(n.ResponseNegData)
		if err != nil {
			return nil, nil, nil, err
		}

		switch n.ResponseNegData.GetResponse().(type) {
		case *NoiseLinkNegotiationDataResponse1_Rejected:
			return negData, nil, nil, nil
		}
		prologue = makePrologue([][]byte{
			n.RemoteNegData,
			n.RemoteNoiseMsg,
			negData,
		}, n.InitString)
	}
	state, err = noise.NewHandshakeState(noise.Config{
		StaticKeypair: s.StaticKeypair,
		Initiator:     true,
		Pattern:       pattern,
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256),
		PeerStatic:    s.PeerStatic,
		Prologue:      prologue,
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

		prologue := makePrologue([][]byte{data}, initString)

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
	RemoteEphemeral []byte
	ResponseNegData *NoiseLinkNegotiationDataResponse1
	ProtocolnName   string
}

func makePrologue(dataSlice [][]byte, initString []byte) []byte {
	var output []byte
	output = append(initString, output...)
	for _, data := range dataSlice {
		dataLen := make([]byte, 2, uint16Size+len(data))
		binary.BigEndian.PutUint16(dataLen, uint16(len(data)))
		output = append(dataLen, data...)
	}
	output = append(output, appPrologue...)
	return output
}
