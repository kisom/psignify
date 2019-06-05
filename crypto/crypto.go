package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/kisom/psignify/base64"
	"github.com/kisom/psignify/signify"
	"golang.org/x/crypto/nacl/auth"
	"golang.org/x/crypto/nacl/box"
)

const (
	chunkSize       = 16385 // "16KB is a reasonable chunk size." sized for base64.
	headerSize      = 72    // uint64 chunk count + 32B public key + 32B tag
	sealedChunkSize = chunkSize + box.Overhead
)

func skipComment(r io.Reader) error {
	c := []byte{0}
	for {
		_, err := r.Read(c)
		if err != nil {
			return err
		}

		if c[0] == 0xa {
			return nil
		}
	}
}

func incrementNonce(nonce *[24]byte) error {
	i := 23
	for {
		if i == -1 {
			return errors.New("signify/crypto: message is too large, nonce reused")
		}

		nonce[i]++
		if nonce[i] != 0 {
			break
		}
		i--
	}
	return nil
}

func seal(pub *signify.Public, message io.Reader, messageLen int, w io.Writer) error {
	if messageLen == 0 {
		return nil
	}

	var shared [32]byte
	edpub, err := pub.ToBox()
	if err != nil {
		return err
	}

	epub, epriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	box.Precompute(&shared, edpub, epriv)

	chunks := messageLen / chunkSize
	if messageLen%chunkSize != 0 {
		chunks++
	}

	// Write the header:
	// +---+------+------+
	// | C | PUBK | TAG  |
	// +---+------+------+
	//
	// The header consists of a network-order-packed uint64
	// containing the number of 16K chunks that are in this
	// message, a 32B ephemeral public key, and a 32B message
	// authentication code.
	header := [headerSize]byte{}
	binary.BigEndian.PutUint64(header[:8], uint64(chunks))

	copy(header[8:], epub[:])
	headerAuth := auth.Sum(header[:40], &shared)
	copy(header[40:], headerAuth[:])

	_, err = w.Write(header[:])
	if err != nil {
		return err
	}

	chunk := make([]byte, chunkSize)
	nonce := [24]byte{}
	for i := 0; i < chunks; i++ {
		n, err := message.Read(chunk)
		if err != nil {
			return err
		}

		out := box.SealAfterPrecomputation(nil, chunk[:n], &nonce, &shared)
		_, err = w.Write(out)
		if err != nil {
			return err
		}

		err = incrementNonce(&nonce)
		if err != nil {
			return err
		}
	}

	return nil
}

// Seal secures a message.
func Seal(publicPath, messagePath, encryptedPath string) error {
	pub, err := signify.LoadPublicKey(publicPath)
	if err != nil {
		return err
	}

	message, err := os.Open(messagePath)
	if err != nil {
		return err
	}
	defer message.Close()

	fi, err := message.Stat()
	if err != nil {
		return err
	}
	messageLen := int(fi.Size())

	if encryptedPath == "" {
		encryptedPath = messagePath + ".enc"
	}

	encrypted, err := os.Create(encryptedPath)
	if err != nil {
		return err
	}
	defer encrypted.Close()
	_, err = encrypted.Write([]byte("untrusted comment: psignify encrypted file\n"))
	if err != nil {
		return err
	}

	encoder := base64.NewEncoder(encrypted)
	defer encoder.Close()

	return seal(pub, message, messageLen, encoder)
}

func open(priv *signify.Private, message io.Reader, w io.Writer) error {
	edpriv, err := priv.ToBox()
	if err != nil {
		return err
	}

	header := [headerSize]byte{}
	n, err := message.Read(header[:])
	if err != nil {
		return err
	} else if n != headerSize {
		return fmt.Errorf("signify/crypto: couldn't read the full header (read %d)", n)
	}

	chunks := binary.BigEndian.Uint64(header[:8])
	epub := [32]byte{}
	copy(epub[:], header[8:])

	shared := [32]byte{}
	box.Precompute(&shared, &epub, edpriv)
	if !auth.Verify(header[40:], header[:40], &shared) {
		return errors.New("signify/crypto: failed to authenticate the message header")
	}

	chunk := make([]byte, sealedChunkSize)
	nonce := [24]byte{}
	for i := uint64(0); i < chunks; i++ {
		n, err := message.Read(chunk)
		if err != nil {
			return err
		}

		out, ok := box.OpenAfterPrecomputation(nil, chunk[:n], &nonce, &shared)
		if !ok {
			return fmt.Errorf("signify/crypto: failed to decrypt chunk=%d", i)
		}

		_, err = w.Write(out)
		if err != nil {
			return err
		}

		err = incrementNonce(&nonce)
		if err != nil {
			return err
		}
	}

	return nil
}

// Open recovers an encrypted message.
func Open(privatePath, encryptedPath, messagePath string) error {
	priv, err := signify.LoadPrivateKey(privatePath)
	if err != nil {
		return err
	}

	encrypted, err := os.Open(encryptedPath)
	if err != nil {
		return err
	}
	defer encrypted.Close()
	err = skipComment(encrypted)
	if err != nil {
		return err
	}

	decoder := base64.NewDecoder(encrypted)

	message, err := os.Create(messagePath)
	if err != nil {
		return err
	}
	defer message.Close()

	return open(priv, decoder, message)
}
