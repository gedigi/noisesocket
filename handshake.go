package noisesocket

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/golang/protobuf/proto"

	"github.com/gedigi/noisesocket/noise"
	"github.com/pkg/errors"
)

var appPrologue = []byte("NLS(revision2)")

func makeInitiatorRequest(s *ConnectionConfig) (negData []byte, n *NoiseLinkNegotiationDataRequest1, err error) {
	if len(s.PeerStatic) != 0 && len(s.PeerStatic) != dhs[NOISE_DH_CURVE25519].DHLen() {
		err = errors.New("only 32 byte curve25519 public keys are supported")
		return nil, nil, err
	}
	n = new(NoiseLinkNegotiationDataRequest1)
	n.ServerName = s.ServerName
	n.InitialProtocol, n.RetryProtocol, n.SwitchProtocol, err =
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
	if err != nil {
		return nil, nil, err
	}
	negData, _ = proto.Marshal(n)
	return
}

func makeInitiatorState(s *ConnectionConfig, prologueData *[][]byte, n *NoiseLinkNegotiationDataRequest1, initString string) (state *noise.HandshakeState, err error) {
	hs, dh, cipher, hash, err := parseProtocolName(n.InitialProtocol)
	if err != nil {
		return nil, err
	}

	prologue := makePrologue(*prologueData, []byte(initString))

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

// ComposeInitiatorHandshakeMessage generates handshakeState and the first noise message.
// func ComposeInitiatorHandshakeMessage(s ConnectionConfig) (
// 	negData []byte,
// 	state *noise.HandshakeState,
// 	err error,
// ) {

// 	if len(s.PeerStatic) != 0 && len(s.PeerStatic) != dhs[NOISE_DH_CURVE25519].DHLen() {
// 		return nil, nil, errors.New("only 32 byte curve25519 public keys are supported")
// 	}

// 	negotiationData := new(NoiseLinkNegotiationDataRequest1)
// 	negotiationData.ServerName = s.ServerName

// 	negotiationData.InitialProtocol, negotiationData.RetryProtocol, negotiationData.SwitchProtocol, err =
// 		func() (in string, re []string, sw []string, err error) {
// 			if len(s.InitialProtocol) != 0 {
// 				if len(s.PeerStatic) == 0 && s.InitialProtocol[6:8] == "IK" {
// 					err = errors.New("IK needs PeerStatic")
// 				} else {
// 					in = s.InitialProtocol
// 					sw = s.SwitchProtocols
// 					re = s.RetryProtocols
// 				}
// 			} else {
// 				if len(s.PeerStatic) == 0 {
// 					in = "Noise_XX_25519_AESGCM_SHA256"
// 				} else {
// 					in = "Noise_IK_25519_AESGCM_SHA256"
// 					sw = []string{"Noise_XXfallback_25519_AESGCM_SHA256"}
// 				}
// 				re = []string{"Noise_XX_25519_ChaChaPoly_SHA256"}
// 			}
// 			return
// 		}()

// 	negData, _ = proto.Marshal(negotiationData)

// 	hs, dh, cipher, hash, err := parseProtocolName(negotiationData.InitialProtocol)
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	prologue := makePrologue([][]byte{negData}, []byte("NoiseSocketInit1"))
// 	state, err = noise.NewHandshakeState(noise.Config{
// 		StaticKeypair: s.StaticKeypair,
// 		Initiator:     true,
// 		Pattern:       patternByteObj[hs],
// 		CipherSuite: noise.NewCipherSuite(
// 			dhByteObj[dh],
// 			cipherByteObj[cipher],
// 			hashByteObj[hash],
// 		),
// 		PeerStatic: s.PeerStatic,
// 		Prologue:   prologue,
// 		Random:     rand.Reader,
// 	})
// 	return
// }

func ParseNegotiationData(data *[]byte, s *ConnectionConfig, prologueData *[][]byte, initString *[]byte) (state *noise.HandshakeState, err error) {

	var (
		ok                   bool
		hs, dh, cipher, hash byte
	)
	dataParsed := new(NoiseLinkNegotiationDataRequest1)
	err = proto.Unmarshal(*data, dataParsed)
	if err != nil {
		panic(err)
	}
	if _, ok = supportedInitialProtocols[dataParsed.InitialProtocol]; !ok {
		return nil, errors.New("unsupported initial protocol")
	}

	hs, dh, cipher, hash, err = parseProtocolName(dataParsed.InitialProtocol)

	prologue := makePrologue(*prologueData, *initString)
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

func makeResponse(protoName string, responseType int) (response []byte, err error) {
	protoResponse := &NoiseLinkNegotiationDataResponse1{}
	switch responseType {
	case RESPONSE_REJECT:
		protoResponse.Response = &NoiseLinkNegotiationDataResponse1_Rejected{
			Rejected: true,
		}
	case RESPONSE_SWITCH:
		protoResponse.Response = &NoiseLinkNegotiationDataResponse1_SwitchProtocol{
			SwitchProtocol: protoName,
		}
	case RESPONSE_RETRY:
		protoResponse.Response = &NoiseLinkNegotiationDataResponse1_RetryProtocol{
			RetryProtocol: protoName,
		}
	default:
		return nil, errors.New("Invalid request data")
	}
	response, _ = proto.Marshal(protoResponse)
	return
}

func makeResponseState(protoName string, prologueData *[][]byte, peerEphemeral []byte, localStatic noise.DHKey, initString []byte) (hs *noise.HandshakeState, err error) {
	if initString != nil {
		prologue := makePrologue(*prologueData, initString)
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
