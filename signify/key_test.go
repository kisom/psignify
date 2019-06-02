package signify

import (
	"bytes"
	"crypto/rand"
	"io/ioutil"
	"os"
	"testing"

	"golang.org/x/crypto/nacl/box"
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
	PassphrasePrompt = func(_ bool) ([]byte, error) {
		return []byte("passphrase"), nil
	}
}

func TestLoadKey(t *testing.T) {
	pub, err := LoadPublicKey(testPublicKey)
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
	defer os.Remove(testSignature2)

	err = Verify(testPublicKey, testMessage2, testSignature2)
	if err != nil {
		t.Fatal(err)
	}
}

func TestEncryption(t *testing.T) {
	priv, pub, err := GenerateKeypair(nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	boxPriv, err := priv.ToBox()
	if err != nil {
		t.Fatal(err)
	}

	boxPub, err := pub.ToBox()
	if err != nil {
		t.Fatal(err)
	}

	epub, epriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("the bird is the word")
	nonce := &[24]byte{}
	out := box.Seal(nil, message, nonce, boxPub, epriv)
	dec, ok := box.Open(nil, out, nonce, epub, boxPriv)
	if !ok {
		t.Fatal("signify: decryption failed")
	}

	if !bytes.Equal(message, dec) {
		t.Logf("message: %x", message)
		t.Logf("decrypt: %x", dec)
		t.Fatal("signify: decryption failed")
	}
}

func TestEncryption2(t *testing.T) {
	priv1, pub1, err := GenerateKeypair(nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	boxPriv1, err := priv1.ToBox()
	if err != nil {
		t.Fatal(err)
	}

	boxPub1, err := pub1.ToBox()
	if err != nil {
		t.Fatal(err)
	}

	priv2, pub2, err := GenerateKeypair(nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	boxPriv2, err := priv2.ToBox()
	if err != nil {
		t.Fatal(err)
	}

	boxPub2, err := pub2.ToBox()
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("the bird is the word")
	nonce := &[24]byte{}
	out := box.Seal(nil, message, nonce, boxPub2, boxPriv1)
	dec, ok := box.Open(nil, out, nonce, boxPub1, boxPriv2)
	if !ok {
		t.Fatal("signify: decryption failed")
	}

	if !bytes.Equal(message, dec) {
		t.Logf("message: %x", message)
		t.Logf("decrypt: %x", dec)
		t.Fatal("signify: decryption failed")
	}

	_, ok = box.Open(nil, out, nonce, boxPub1, boxPriv1)
	if ok {
		t.Fatal("signify: decryption should fail")
	}
}
