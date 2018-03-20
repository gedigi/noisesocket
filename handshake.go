package noisesocket

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/golang/protobuf/proto"

	"github.com/gedigi/noisesocket/noise"
	"github.com/pkg/errors"
)

var appPrologue = []byte("NLS(revision2)")

// ComposeInitiatorHandshakeMessage generates handshakeState and the first noise message.
func ComposeInitiatorHandshakeMessage(s ConnectionConfig) (
	negData, msg []byte,
	state *noise.HandshakeState,
	err error,
) {

	if len(s.PeerStatic) != 0 && len(s.PeerStatic) != dhs[s.DHFunc].DHLen() {
		return nil, nil, nil, errors.New("only 32 byte curve25519 public keys are supported")
	}

	negotiationData := new(NoiseLinkNegotiationDataRequest1)
	negotiationData.ServerName = s.ServerName

	if len(s.PeerStatic) == 0 {
		negotiationData.InitialProtocol = "Noise_XX_25519_AESGCM_SHA256"
	} else {
		negotiationData.InitialProtocol = "Noise_IK_25519_AESGCM_SHA256"
		negotiationData.SwitchProtocol = []string{"Noise_XXfallback_25519_AESGCM_SHA256"}
	}

	negData, _ = proto.Marshal(negotiationData)

	hs, dh, cipher, hash, err := parseProtocolName(negotiationData.InitialProtocol)
	if err != nil {
		return nil, nil, nil, err
	}

	prologue := makePrologue([][]byte{negData}, []byte("NoiseSocketInit1"))
	state, err = noise.NewHandshakeState(noise.Config{
		StaticKeypair: s.StaticKeypair,
		Initiator:     true,
		Pattern:       patternByteObj[hs],
		CipherSuite: noise.NewCipherSuite(
			dhByteObj[dh],
			cipherByteObj[cipher],
			hashByteObj[hash],
		),
		PeerStatic: s.PeerStatic,
		Prologue:   prologue,
		Random:     rand.Reader,
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
	dataParsed := new(NoiseLinkNegotiationDataRequest1)
	err = proto.Unmarshal(data, dataParsed)
	if err != nil {
		panic(err)
	}
	if _, ok = supportedInitialProtocols[dataParsed.InitialProtocol]; !ok {
		return nil, errors.New("unsupported initial protocol")
	}

	hs, dh, cipher, hash, err = parseProtocolName(dataParsed.InitialProtocol)

	prologue := makePrologue([][]byte{data}, []byte("NoiseSocketInit1"))
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

func makePrologue(dataSlice [][]byte, initString []byte) (output []byte) {
	output = append(initString, output...)
	for _, data := range dataSlice {
		dataLen := make([]byte, 2, uint16Size+len(data))
		binary.BigEndian.PutUint16(dataLen, uint16(len(data)))
		output = append(output, dataLen...)
		output = append(output, data...)
	}
	output = append(output, appPrologue...)
	return
}

// NegotiationData struct
type negotiationData struct {
	Encoded []byte
	Raw     proto.Message
}

func newNegotiationData(t interface{}) (n negotiationData, err error) {
	// n = &negotiationData{}
	switch tType := t.(type) {
	case []byte:
		n.Encoded = t.([]byte)
		err = proto.Unmarshal(n.Encoded, n.Raw)
	case proto.Message:
		n.Raw = t.(proto.Message)
		n.Encoded, err = proto.Marshal(n.Raw)
	default:
		err = errors.Errorf("Can't handle type %T", tType)
	}
	return
}

func makeResponse(protoName string, responseType string, prologueData [][]byte, peerEphemeral []byte) (response []byte, hs *noise.HandshakeState, err error) {
	var initString []byte
	protoResponse := &NoiseLinkNegotiationDataResponse1{}
	switch responseType {
	case "reject":
		protoResponse.Response = &NoiseLinkNegotiationDataResponse1_Rejected{
			Rejected: true,
		}
	case "switch":
		protoResponse.Response = &NoiseLinkNegotiationDataResponse1_SwitchProtocol{
			SwitchProtocol: protoName,
		}
		initString = []byte("NoiseSocketInit3")
	case "retry":
		protoResponse.Response = &NoiseLinkNegotiationDataResponse1_RetryProtocol{
			RetryProtocol: protoName,
		}
		initString = []byte("NoiseSocketInit2")
	default:
		return nil, nil, errors.New("Invalid request data")
	}
	if initString != nil {
		response, _ = proto.Marshal(protoResponse)
		prologue := makePrologue(prologueData, initString)
		pattern, dh, cipher, hash, _ := parseProtocolName(protoName)
		hs, err = noise.NewHandshakeState(noise.Config{
			StaticKeypair: hs.LocalStatic(),
			Initiator:     true,
			Pattern:       patternByteObj[pattern],
			CipherSuite: noise.NewCipherSuite(
				dhByteObj[dh],
				cipherByteObj[cipher],
				hashByteObj[hash],
			),
			Prologue:      prologue,
			Random:        rand.Reader,
			PeerEphemeral: peerEphemeral,
		})
	}
	return
}
