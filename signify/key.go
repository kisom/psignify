package signify

import "fmt"

const (
	keyNumLength    = 8
	secretKeyLength = 32
	publicKeyLength = 32
	keyAlgoLength   = 2
	saltLength      = 16
	checksumLength  = 8
)

/*
struct enckey {
        uint8_t pkalg[2];
        uint8_t kdfalg[2];
        uint32_t kdfrounds;
        uint8_t salt[16];
        uint8_t checksum[8];
        uint8_t keynum[KEYNUMLEN];
        uint8_t seckey[SECRETBYTES];
};

struct pubkey {
        uint8_t pkalg[2];
        uint8_t keynum[KEYNUMLEN];
        uint8_t pubkey[PUBLICBYTES];
};
*/

// Private is a Signify private key.
type Private struct {
	Comment   string
	keyAlgo   [keyAlgoLength]uint8
	kdfAlgo   uint8
	kdfRounds uint32
	salt      [saltLength]uint8
	checksum  [checksumLength]uint8
	keyNum    [keyNumLength]uint8
	key       [secretKeyLength]uint8
}

// TODO: load key
// TODO: decrypt key
// TODO: decrypt data
// TODO: sign data

// Public is a Signify public key.
type Public struct {
	keyAlgo [keyAlgoLength]uint8
	keyNum  [keyNumLength]uint8
	key     [publicKeyLength]byte
}

func (pub *Public) KeyID() uint64 {
	// TODO: parse uint64
}

func LoadPublic(data []byte) (*Public, error) {
	// TODO: base64 decode

	if len(data) != (keyAlgoLength + keyNumLength + publicKeyLength) {
		return fmt.Errorf("signify: invalid public key length %d", len(data))
	}

	// TODO: parse key based on algorithm
}

// TODO: signature verification
// TODO: X25519 PK
