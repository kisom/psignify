package crypto

import (
	"bytes"
	"testing"
)

func TestEncodeDecode(t *testing.T) {
	header := [72]byte{}
	for i := 0; i < 72; i++ {
		header[i] = byte(i)
	}

	out := &bytes.Buffer{}
	enc := newEncoder(out)
	n, err := enc.Write(header[:])
	if err != nil {
		t.Fatal(err)
	} else if n != 72 {
		t.Fatalf("signify/crypto: short write: %d != 72", n)
	}

	dec := newDecoder(out)
	header2 := make([]byte, 72)
	n, err = dec.Read(header2)
	if err != nil {
		t.Fatal(err)
	} else if n != 72 {
		t.Fatalf("signify/crypto: short read: %d != 72", n)
	}

	if !bytes.Equal(header[:], header2) {
		t.Logf(" header: %x", header)
		t.Logf("header2: %x", header2)
		t.Fatal("signify/crypto: invalid decoding")
	}
}
