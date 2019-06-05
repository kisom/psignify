package crypto

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"github.com/kisom/psignify/signify"
)

const (
	testMessageFile   = "testdata/meditations.txt"
	testEncryptedFile = "testdata/meditations.txt.enc"
	testDecryptedFile = "testdata/meditations2.txt"
	testPublicKey     = "testdata/test.pub"
	testPrivateKey    = "testdata/test.sec"
)

func TestSealUnseal(t *testing.T) {
	priv, pub, err := signify.GenerateKeypair(nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	err = priv.Check()
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := ioutil.ReadFile(testMessageFile)
	if err != nil {
		t.Fatal(err)
	}

	pbuf := bytes.NewBuffer(plaintext)
	ebuf := &bytes.Buffer{}

	err = seal(pub, pbuf, len(plaintext), ebuf)
	if err != nil {
		t.Fatal(err)
	}

	dbuf := &bytes.Buffer{}
	err = open(priv, ebuf, dbuf)
	if err != nil {
		t.Fatal(err)
	}

	decrypted := dbuf.Bytes()
	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("signify/crypto: invalid decryption")
	}
}

func TestSeal(t *testing.T) {
	err := Seal(testPublicKey, testMessageFile, "")
	if err != nil {
		t.Fatal(err)
	}
}

func TestOpen(t *testing.T) {
	defer os.Remove(testEncryptedFile)
	defer os.Remove(testDecryptedFile)
	err := Open(testPrivateKey, testEncryptedFile, testDecryptedFile)
	if err != nil {
		t.Fatal(err)
	}

	original, err := ioutil.ReadFile(testMessageFile)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := ioutil.ReadFile(testDecryptedFile)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(original, decrypted) {
		t.Fatal("signify/crypto: decryption didn't produce the matching message")
	}
}
