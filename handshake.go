package noisesocket

import (
	"encoding/binary"

	"github.com/gedigi/noisesocket/noise"
	proto "github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
)

var negotiationData []byte
var appPrologue = []byte("NLS(revision1)")
var fallback = true

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
		pattern, dh, hash, cipher byte
		protoName                 string
	)

	if len(s.PeerStatic) != 0 && len(s.PeerStatic) != dhs[s.DHFunc].DHLen() {
		return nil, nil, nil, errors.New("only 32 byte curve25519 public keys are supported")
	}

	nConfig := noise.Config{
		StaticKeypair: s.StaticKeypair,
		Initiator:     true,
		PeerStatic:    s.PeerStatic,
	}
	if n.ResponseNegData == nil {

		negotiationDataNLS := &NoiseLinkNegotiationDataRequest1{}
		negotiationDataNLS.ServerName = s.ServerHostname
		if len(s.PeerStatic) == 0 {
			negotiationDataNLS.InitialProtocol = "Noise_XX_25519_AESGCM_SHA256"
			negotiationDataNLS.RetryProtocol = []string{"Noise_XX_25519_ChaChaPoly_SHA256"}
		} else {
			negotiationDataNLS.InitialProtocol = "Noise_IK_25519_AESGCM_SHA256"
			negotiationDataNLS.SwitchProtocol = []string{"Noise_XXfallback_25519_AESGCM_SHA256"}
			negotiationDataNLS.RetryProtocol = []string{"Noise_XX_25519_ChaChaPoly_SHA256"}
		}

		negData, err = proto.Marshal(negotiationDataNLS)
		if err != nil {
			return nil, nil, nil, errors.New("Invalid negotiation data")
		}

		protoName = negotiationDataNLS.InitialProtocol
		nConfig.Prologue = makePrologue([][]byte{negData}, n.InitString)
	} else {
		switch n.ResponseNegData.Raw.GetResponse().(type) {
		case *NoiseLinkNegotiationDataResponse1_Rejected:
			return negData, nil, nil, nil
		}
		nConfig.Prologue = makePrologue([][]byte{
			n.RemoteNegData,
			n.RemoteNoiseMsg,
			negData,
		}, n.InitString)
		protoName = n.ProtocolName
		if n.RemoteEphemeral != nil {
			nConfig.PeerEphemeral = n.RemoteEphemeral
		}
	}
	pattern, dh, cipher, hash, _, err = parseProtocolName(protoName)
	if err != nil {
		return nil, nil, nil, err
	}
	nConfig.Pattern = patternByteObj[pattern]
	nConfig.CipherSuite = noise.NewCipherSuite(
		dhByteObj[dh],
		cipherByteObj[cipher],
		hashByteObj[hash],
	)

	state, err = noise.NewHandshakeState(nConfig)

	if err != nil {
		return nil, nil, nil, err
	}

	msg, _, _, err = state.WriteMessage(msg, s.Payload)

	return
}

func ParseInitiatorData(s ConnectionConfig, negotiationData negoRequest, InitiatorNoiseMsg []byte) (
	response negoResponse,
	msg []byte,
	state *noise.HandshakeState,
	payload []byte,
	err error,
) {
	var pattern, dh, cipher, hash byte

	initialProtocol := negotiationData.Raw.GetInitialProtocol()
	nConfig := noise.Config{
		StaticKeypair: s.StaticKeypair,
	}

	if _, ok := supportedProtocols[initialProtocol]; ok {
		// Initial Protocol is supported

		var initString = []byte("NoiseSocketInit1")
		pattern, dh, cipher, hash, _, err = parseProtocolName(initialProtocol)
		if err != nil {
			return negoResponse{}, nil, nil, nil, err
		}
		nConfig.Pattern = patternByteObj[pattern]
		nConfig.CipherSuite = noise.NewCipherSuite(
			dhByteObj[dh],
			cipherByteObj[cipher],
			hashByteObj[hash],
		)
		nConfig.Prologue = makePrologue([][]byte{negotiationData.Encoded}, initString)
		state, err = noise.NewHandshakeState(nConfig)
		if err != nil {
			return negoResponse{}, nil, nil, nil, err
		}
		payload, _, _, err = state.ReadMessage(nil, InitiatorNoiseMsg)
		if err != nil {
			// Switch to fallback if it can't decrypt
			var negData []byte
			switchProtocols := negotiationData.Raw.GetSwitchProtocol()
			for _, pName := range switchProtocols {
				if _, ok := supportedProtocols[pName]; ok {
					r := &NoiseLinkNegotiationDataResponse1{
						Response: &NoiseLinkNegotiationDataResponse1_SwitchProtocol{
							SwitchProtocol: pName,
						},
					}
					response, _ = newNegoResponse(r)
					negData, msg, state, err = InitiatorHandshake(s, NegotiationData{
						ProtocolName:    pName,
						RemoteNoiseMsg:  InitiatorNoiseMsg,
						RemoteNegData:   negotiationData.Encoded,
						InitString:      []byte("NoiseSocketInit2"),
						RemoteEphemeral: state.PeerEphemeral(),
						ResponseNegData: &response,
					})
					break
				}
			}
			if negData == nil {
				goto retryProtocol
			}
			msg, _, _, err = state.WriteMessage(msg, s.Payload)
			return
		}
		return
	}
retryProtocol:
	// Use retry protocol if not supported
	var negData []byte

	retryProtocols := negotiationData.Raw.GetRetryProtocol()
	for _, pName := range retryProtocols {
		if _, ok := supportedProtocols[pName]; ok {
			r := &NoiseLinkNegotiationDataResponse1{
				Response: &NoiseLinkNegotiationDataResponse1_RetryProtocol{
					RetryProtocol: pName,
				},
			}
			response, _ = newNegoResponse(r)
			negData, msg, state, err = InitiatorHandshake(s, NegotiationData{
				ProtocolName:    pName,
				RemoteNoiseMsg:  InitiatorNoiseMsg,
				RemoteNegData:   negotiationData.Encoded,
				InitString:      []byte("NoiseSocketInit3"),
				ResponseNegData: &response,
			})
			break
		}
	}
	if negData == nil {
		goto rejectProtocol
	}
	msg, _, _, err = state.WriteMessage(msg, s.Payload)
	return
rejectProtocol:
	// Reject
	r := &NoiseLinkNegotiationDataResponse1{
		Response: &NoiseLinkNegotiationDataResponse1_Rejected{
			Rejected: true,
		},
	}
	response, _ = newNegoResponse(r)
	return response, nil, nil, nil, nil
}

// NegotiationData holds information related to the negotiation_data field
type NegotiationData struct {
	InitString      []byte
	RemoteNoiseMsg  []byte
	RemoteNegData   []byte
	RemoteEphemeral []byte
	ResponseNegData *negoResponse
	ProtocolName    string
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
	// log.Printf("%+v", output)
	return output
}
