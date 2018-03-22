package noisesocket

import (
	"regexp"

	"github.com/gedigi/noisesocket/noise"
	"github.com/pkg/errors"
)

//supported primitives

//from noise-c https://github.com/rweather/noise-c/blob/master/include/noise/protocol/constants.h
const (
	NOISE_DH_CURVE25519 = 1

	NOISE_CIPHER_CHACHAPOLY = 1
	NOISE_CIPHER_AESGCM     = 2

	NOISE_HASH_BLAKE2s = 1
	NOISE_HASH_BLAKE2b = 2
	NOISE_HASH_SHA256  = 3
	NOISE_HASH_SHA512  = 4

	NOISE_PATTERN_XX          = 9
	NOISE_PATTERN_IK          = 14
	NOISE_PATTERN_XX_FALLBACK = 16
)

const (
	RESPONSE_SWITCH = iota
	RESPONSE_RETRY
	RESPONSE_REJECT
)

var dhs = map[byte]noise.DHFunc{
	NOISE_DH_CURVE25519: noise.DH25519,
}

var ciphers = map[byte]noise.CipherFunc{
	NOISE_CIPHER_CHACHAPOLY: noise.CipherChaChaPoly,
	NOISE_CIPHER_AESGCM:     noise.CipherAESGCM,
}

var hashes = map[byte]noise.HashFunc{
	// NOISE_HASH_BLAKE2s: noise.HashBLAKE2s,
	// NOISE_HASH_BLAKE2b: noise.HashBLAKE2b,
	NOISE_HASH_SHA256: noise.HashSHA256,
	// NOISE_HASH_SHA512:  noise.HashSHA512,
}

var patterns = map[byte]noise.HandshakePattern{
	NOISE_PATTERN_XX:          noise.HandshakeXX,
	NOISE_PATTERN_IK:          noise.HandshakeIK,
	NOISE_PATTERN_XX_FALLBACK: noise.HandshakeXXfallback,
}

var supportedInitialProtocols = map[string]byte{
	"Noise_IK_25519_AESGCM_SHA256":     0,
	"Noise_IK_25519_ChaChaPoly_SHA256": 1,
	"Noise_XX_25519_AESGCM_SHA256":     2,
	"Noise_XX_25519_ChaChaPoly_SHA256": 3,
}
var supportedRetryProtocols = map[string]byte{
	"Noise_XX_25519_AESGCM_SHA256":     0,
	"Noise_XX_25519_ChaChaPoly_SHA256": 1,
}
var supportedSwitchProtocols = map[string]byte{
	"Noise_XXfallback_25519_AESGCM_SHA256":     0,
	"Noise_XXfallback_25519_ChaChaPoly_SHA256": 1,
}

// Handshake Patterns
var patternStrByte = map[string]byte{
	"XX":         NOISE_PATTERN_XX,
	"IK":         NOISE_PATTERN_IK,
	"XXfallback": NOISE_PATTERN_XX_FALLBACK,
}

var patternByteObj = map[byte]noise.HandshakePattern{
	NOISE_PATTERN_XX:          noise.HandshakeXX,
	NOISE_PATTERN_IK:          noise.HandshakeIK,
	NOISE_PATTERN_XX_FALLBACK: noise.HandshakeXXfallback,
}

// DH Funcs
var dhStrByte = map[string]byte{
	"25519": NOISE_DH_CURVE25519,
}

var dhByteObj = map[byte]noise.DHFunc{
	NOISE_DH_CURVE25519: noise.DH25519,
}

// Cipher Funcs
var cipherStrByte = map[string]byte{
	"ChaChaPoly": NOISE_CIPHER_CHACHAPOLY,
	"AESGCM":     NOISE_CIPHER_AESGCM,
}

var cipherByteObj = map[byte]noise.CipherFunc{
	NOISE_CIPHER_CHACHAPOLY: noise.CipherChaChaPoly,
	NOISE_CIPHER_AESGCM:     noise.CipherAESGCM,
}

// Hash Funcs
var hashStrByte = map[string]byte{
	"SHA256": NOISE_HASH_SHA256,
	"SHA512": NOISE_HASH_SHA512,
}

var hashByteObj = map[byte]noise.HashFunc{
	NOISE_HASH_SHA256: noise.HashSHA256,
	NOISE_HASH_SHA512: noise.HashSHA512,
}

func parseProtocolName(protoName string) (
	hs byte,
	dh byte,
	cipher byte,
	hash byte,
	err error,
) {
	var ok bool
	regEx := regexp.MustCompile(`Noise_(\w+)_(\w+)_(\w+)_(\w+)`)
	results := regEx.FindStringSubmatch(protoName)
	if len(results) == 5 {
		if hs, ok = patternStrByte[results[1]]; ok == false {
			err = errors.New("Unsupported handshake pattern")
			return
		}
		if dh, ok = dhStrByte[results[2]]; ok == false {
			err = errors.New("Unsupported DH function")
			return
		}
		if cipher, ok = cipherStrByte[results[3]]; ok == false {
			err = errors.New("Unsupported cipher function")
			return
		}
		if hash, ok = hashStrByte[results[4]]; ok == false {
			err = errors.New("Unsupported hash function")
			return
		}
	} else {
		err = errors.New("Invalid protocol name")
	}
	return
}
