package signify

import "golang.org/x/crypto/ed25519"

const signatureLength = ed25519.SignatureSize

type Signature struct {
	pkAlgo [2]uint8
	keyNum [keyNumLength]uint8
	sig    [signatureLength]uint8
}
