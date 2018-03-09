package noisesocket

import (
	"encoding/binary"
	"log"

	"crypto/rand"

	"bytes"
	"io"

	"github.com/gedigi/noise"
	"github.com/pkg/errors"
)

var negotiationData []byte
var initString = []byte("NoiseSocketInit1")

func init() {
	negotiationData = make([]byte, 6)
	binary.BigEndian.PutUint16(negotiationData, 1) //version
}

// ComposeInitiatorHandshakeMessage generates handshakeState and the first noise message.
func ComposeInitiatorHandshakeMessage(s ConnectionConfig, rs []byte, payload []byte, ePrivate []byte) (negData, msg []byte, state *noise.HandshakeState, err error) {

	if len(rs) != 0 && len(rs) != dhs[s.DHFunc].DHLen() {
		return nil, nil, nil, errors.New("only 32 byte curve25519 public keys are supported")
	}
	var pattern noise.HandshakePattern

	negotiationData[2] = s.DHFunc
	negotiationData[3] = s.CipherFunc
	negotiationData[4] = s.HashFunc

	negData = make([]byte, 6)
	copy(negData, negotiationData)

	if len(rs) == 0 {
		pattern = noise.HandshakeXX
		negData[5] = NOISE_PATTERN_XX
	} else {
		pattern = noise.HandshakeIK
		negData[5] = NOISE_PATTERN_IK
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
	log.Printf("%+v", prologue)
	state, err = noise.NewHandshakeState(noise.Config{
		StaticKeypair: s.StaticKeypair,
		Initiator:     true,
		Pattern:       pattern,
		CipherSuite:   noise.NewCipherSuite(dhs[s.DHFunc], ciphers[s.CipherFunc], hashes[s.HashFunc]),
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

	if len(data) != 6 {
		return nil, errors.New("Invalid negotiation data length")
	}

	var ok bool
	var dh noise.DHFunc
	var cipher noise.CipherFunc
	var hash noise.HashFunc
	var pattern noise.HandshakePattern

	version := binary.BigEndian.Uint16(data)
	if version != 1 {
		return nil, errors.New("unsupported version")
	}

	dhIndex := data[2]
	if dh, ok = dhs[dhIndex]; !ok {
		return nil, errors.New("unsupported DH")
	}

	cipherIndex := data[3]
	if cipher, ok = ciphers[cipherIndex]; !ok {
		return nil, errors.New("unsupported cipher")
	}

	hashIndex := data[4]
	if hash, ok = hashes[hashIndex]; !ok {
		return nil, errors.New("unsupported hash")
	}

	patternIndex := data[5]

	if pattern, ok = patterns[patternIndex]; !ok {
		return nil, errors.New("unsupported pattern")
	}

	prologue := make([]byte, 2, uint16Size+len(data))
	binary.BigEndian.PutUint16(prologue, uint16(len(data)))
	prologue = append(prologue, data...)
	prologue = append(initString, prologue...)
	state, err = noise.NewHandshakeState(noise.Config{
		StaticKeypair: s.StaticKeypair,
		Pattern:       pattern,
		CipherSuite:   noise.NewCipherSuite(dh, cipher, hash),
		Prologue:      prologue,
	})
	return
}
