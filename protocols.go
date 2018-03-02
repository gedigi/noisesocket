package noisesocket

import "github.com/gedigi/noise"

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

	NOISE_PATTERN_XX = 9
	NOISE_PATTERN_IK = 14
)

var dhs = map[byte]noise.DHFunc{
	NOISE_DH_CURVE25519: noise.DH25519,
}

var ciphers = map[byte]noise.CipherFunc{
	NOISE_CIPHER_CHACHAPOLY: noise.CipherChaChaPoly,
	NOISE_CIPHER_AESGCM:     noise.CipherAESGCM,
}

var hashes = map[byte]noise.HashFunc{
	NOISE_HASH_BLAKE2s: noise.HashBLAKE2s,
	NOISE_HASH_BLAKE2b: noise.HashBLAKE2b,
	NOISE_HASH_SHA256:  noise.HashSHA256,
	NOISE_HASH_SHA512:  noise.HashSHA512,
}

var patterns = map[byte]noise.HandshakePattern{
	NOISE_PATTERN_XX: noise.HandshakeXX,
	NOISE_PATTERN_IK: noise.HandshakeIK,
}
