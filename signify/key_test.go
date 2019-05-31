package signify

import (
	"bytes"
	"io/ioutil"
	"testing"
)

const (
	testMessage    = "testdata/message.txt"
	testMessage2   = "testdata/test.txt"
	testPrivateKey = "testdata/test.sec"
	testPublicKey  = "testdata/test.pub"
	testSignature  = "testdata/message.txt.sig"
	testSignature2 = "testdata/test.txt.sig"
)

var testPublicKeyNum = []byte{0x98, 0xce, 0x92, 0xfb, 0x7e, 0x8c, 0x04, 0xd1}

func init() {
	PassphrasePrompt = func() ([]byte, error) {
		return []byte("passphrase"), nil
	}
}

func TestLoadKey(t *testing.T) {
	pub, err := readPublicKeyPath(testPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(testPublicKeyNum, pub.keyNum[:]) {
		t.Fatalf("signify: invalid public key number %x, want %x", pub.keyNum, testPublicKeyNum)
	}

	message, err := ioutil.ReadFile(testMessage)
	if err != nil {
		t.Fatal(err)
	}

	signature, err := readSignaturePath(testSignature)
	if err != nil {
		t.Fatal(err)
	}

	err = pub.verifyEd25519(message, signature)
	if err != nil {
		t.Fatal(err)
	}

}

func TestSign(t *testing.T) {
	err := Sign(testPrivateKey, testMessage2, "")
	if err != nil {
		t.Fatal(err)
	}

	err = Verify(testPublicKey, testMessage2, testSignature2)
	if err != nil {
		t.Fatal(err)
	}
}
