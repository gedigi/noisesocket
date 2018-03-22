package noisesocket

import (
	"crypto/rand"
	"encoding/binary"
	"log"

	"github.com/golang/protobuf/proto"

	"github.com/gedigi/noisesocket/noise"
	"github.com/pkg/errors"
)

var appPrologue = []byte("NLS(revision2)")

// ComposeInitiatorHandshakeMessage generates handshakeState and the first noise message.
func ComposeInitiatorHandshakeMessage(s ConnectionConfig) (
	negData []byte,
	state *noise.HandshakeState,
	err error,
) {

	if len(s.PeerStatic) != 0 && len(s.PeerStatic) != dhs[NOISE_DH_CURVE25519].DHLen() {
		return nil, nil, errors.New("only 32 byte curve25519 public keys are supported")
	}

	negotiationData := new(NoiseLinkNegotiationDataRequest1)
	negotiationData.ServerName = s.ServerName

	negotiationData.InitialProtocol, negotiationData.RetryProtocol, negotiationData.SwitchProtocol, err =
		func() (in string, re []string, sw []string, err error) {
			if len(s.InitialProtocol) != 0 {
				if len(s.PeerStatic) == 0 && s.InitialProtocol[6:8] == "IK" {
					err = errors.New("IK needs PeerStatic")
				} else {
					in = s.InitialProtocol
					sw = s.SwitchProtocols
					re = s.RetryProtocols
				}
			} else {
				if len(s.PeerStatic) == 0 {
					in = "Noise_XX_25519_AESGCM_SHA256"
				} else {
					in = "Noise_IK_25519_AESGCM_SHA256"
					sw = []string{"Noise_XXfallback_25519_AESGCM_SHA256"}
				}
				re = []string{"Noise_XX_25519_ChaChaPoly_SHA256"}
			}
			return
		}()

	negData, _ = proto.Marshal(negotiationData)

	hs, dh, cipher, hash, err := parseProtocolName(negotiationData.InitialProtocol)
	if err != nil {
		return nil, nil, err
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
	log.Printf("output %s\n%v", output, output)
	return
}

func makeResponse(protoName string, responseType string, prologueData [][]byte, peerEphemeral []byte, localStatic noise.DHKey) (response []byte, hs *noise.HandshakeState, err error) {
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
		initString = []byte("NoiseSocketInit2")
	case "retry":
		protoResponse.Response = &NoiseLinkNegotiationDataResponse1_RetryProtocol{
			RetryProtocol: protoName,
		}
		initString = []byte("NoiseSocketInit3")
	default:
		return nil, nil, errors.New("Invalid request data")
	}
	if initString != nil {
		response, _ = proto.Marshal(protoResponse)
		prologue := makePrologue(append(prologueData, [][]byte{response}...), initString)
		pattern, dh, cipher, hash, _ := parseProtocolName(protoName)
		hs, err = noise.NewHandshakeState(noise.Config{
			StaticKeypair: localStatic,
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
