package noisesocket

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/golang/protobuf/proto"

	"github.com/gedigi/noisesocket/noise"
	"github.com/pkg/errors"
)

var appPrologue = []byte("NLS(revision2)")

func makeInitiatorRequest(s *ConnectionConfig, hp *handshakeParams) (negData []byte, n *NoiseLinkNegotiationDataRequest1, err error) {
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
					hp.peerStatic = s.PeerStatic
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
	hp.currentProtoName = s.InitialProtocol
	hp.prologue = [][]byte{negData}
	hp.localStatic = s.StaticKeypair
	return
}

func (hp *handshakeParams) makeInitiatorState(initString string) (state *noise.HandshakeState, err error) {
	pattern, dh, cipher, hash, err := parseProtocolName(hp.currentProtoName)

	prologue := hp.makePrologue([]byte(initString))

	state, err = noise.NewHandshakeState(noise.Config{
		StaticKeypair: hp.localStatic,
		Initiator:     true,
		Pattern:       patternByteObj[pattern],
		CipherSuite: noise.NewCipherSuite(
			dhByteObj[dh],
			cipherByteObj[cipher],
			hashByteObj[hash],
		),
		PeerStatic:    hp.peerStatic,
		PeerEphemeral: hp.peerEphemeral,
		Prologue:      prologue,
		Random:        rand.Reader,
	})
	return
}

func ParseNegotiationData(data *[]byte, s *ConnectionConfig, hp *handshakeParams) (err error) {

	var ok bool

	dataParsed := new(NoiseLinkNegotiationDataRequest1)
	err = proto.Unmarshal(*data, dataParsed)
	if err != nil {
		panic(err)
	}
	if _, ok = supportedInitialProtocols[dataParsed.InitialProtocol]; !ok {
		err = errors.New("unsupported initial protocol")
		return
	}
	hp.currentProtoName = dataParsed.InitialProtocol
	hp.prologue = append(hp.prologue, [][]byte{*data}...)
	hp.localStatic = s.StaticKeypair
	return
}

func (hp *handshakeParams) makePrologue(initString []byte) (output []byte) {
	output = append(initString, output...)
	for _, data := range hp.prologue {
		dataLen := make([]byte, 2, uint16Size+len(data))
		binary.BigEndian.PutUint16(dataLen, uint16(len(data)))
		output = append(output, dataLen...)
		output = append(output, data...)
	}
	output = append(output, appPrologue...)
	return
}

func (hp *handshakeParams) makeResponse(responseType int) (response []byte, err error) {
	protoResponse := &NoiseLinkNegotiationDataResponse1{}
	switch responseType {
	case RESPONSE_REJECT:
		protoResponse.Response = &NoiseLinkNegotiationDataResponse1_Rejected{
			Rejected: true,
		}
	case RESPONSE_SWITCH:
		protoResponse.Response = &NoiseLinkNegotiationDataResponse1_SwitchProtocol{
			SwitchProtocol: hp.currentProtoName,
		}
	case RESPONSE_RETRY:
		protoResponse.Response = &NoiseLinkNegotiationDataResponse1_RetryProtocol{
			RetryProtocol: hp.currentProtoName,
		}
	default:
		return nil, errors.New("Invalid request data")
	}
	response, _ = proto.Marshal(protoResponse)
	return
}

func (hp *handshakeParams) makeResponseState(initString string) (hs *noise.HandshakeState, err error) {
	prologue := hp.makePrologue([]byte(initString))
	pattern, dh, cipher, hash, _ := parseProtocolName(hp.currentProtoName)
	nc := noise.Config{
		StaticKeypair: hp.localStatic,
		Pattern:       patternByteObj[pattern],
		CipherSuite: noise.NewCipherSuite(
			dhByteObj[dh],
			cipherByteObj[cipher],
			hashByteObj[hash],
		),
		Prologue:      prologue,
		Random:        rand.Reader,
		PeerEphemeral: hp.peerEphemeral,
	}
	if hp.localEphemeral.Public != nil && hp.localEphemeral.Private != nil {
		nc.EphemeralKeypair = hp.localEphemeral
	}
	hs, err = noise.NewHandshakeState(nc)
	return
}

type handshakeParams struct {
	prologue    [][]byte
	allowSwitch bool

	localStatic    noise.DHKey
	localEphemeral noise.DHKey
	peerEphemeral  []byte
	peerStatic     []byte

	currentProtoName string
}
