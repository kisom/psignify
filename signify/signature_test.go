package signify

import (
	"io/ioutil"
	"testing"
)

func TestReadSignature(t *testing.T) {
	sigdata, err := ioutil.ReadFile("testdata/message.txt.sig")
	if err != nil {
		t.Fatal(err)
	}

	sig, err := readSignatureFile(sigdata)
	if err != nil {
		t.Fatal(err)
	}

	sigPKAlgo := string(sig.pkAlgo[:])
	if sigPKAlgo != "Ed" {
		t.Fatalf("signify: invalid public-key algorithm in signature: have %s, want Ed", sigPKAlgo)
	}
}
