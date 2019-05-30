package signify

import (
	"golang.org/x/crypto/ed25519"
)

const signatureLength = ed25519.SignatureSize

type Signature struct {
	pkAlgo [2]uint8
	keyNum [keyNumLength]uint8
	sig    [signatureLength]uint8
}

func readSignatureData(data []byte) (*Signature, error) {
	sig := &Signature{}
	copy(sig.pkAlgo[:], data[:2])
	copy(sig.keyNum[:], data[2:keyNumLength+2])
	copy(sig.sig[:], data[keyNumLength+2:])
	return sig, nil
}

func readSignatureFile(data []byte) (*Signature, error) {
	dat, err := readDataFileBytes(data)
	if err != nil {
		return nil, err
	}

	return readSignatureData(dat.data)
}
