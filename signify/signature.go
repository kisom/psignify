package signify

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"

	"golang.org/x/crypto/ed25519"
)

const signatureLength = ed25519.SignatureSize

type Signature struct {
	pkAlgo [keyAlgoLength]uint8
	keyNum [keyNumLength]uint8
	sig    [signatureLength]uint8
}

func (sig *Signature) Encode() []byte {
	buf := &bytes.Buffer{}
	buf.Write(sig.pkAlgo[:])
	buf.Write(sig.keyNum[:])
	buf.Write(sig.sig[:])

	out := make([]byte, base64.StdEncoding.EncodedLen(buf.Len()))
	base64.StdEncoding.Encode(out, buf.Bytes())
	return out
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

func readSignaturePath(path string) (*Signature, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return readSignatureFile(data)
}
