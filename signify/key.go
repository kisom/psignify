package signify

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/dchest/bcrypt_pbkdf"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	keyNumLength    = 8
	secretKeyLength = 64
	publicKeyLength = 32
	keyAlgoLength   = 2
	kdfAlgoLength   = 2
	saltLength      = 16
	checksumLength  = 8
)

var PassphrasePrompt = func() ([]byte, error) {
	return terminal.ReadPassword(0)
}

// Private is a Signify private key.
type Private struct {
	keyAlgo   [keyAlgoLength]uint8
	kdfAlgo   [kdfAlgoLength]uint8
	kdfRounds uint32
	salt      [saltLength]uint8
	checksum  [checksumLength]uint8
	keyNum    [keyNumLength]uint8
	key       [secretKeyLength]uint8
}

func (priv *Private) IsEncrypted() bool {
	return priv.kdfRounds > 0
}

func (priv *Private) check() error {
	digest := sha512.Sum512(priv.key[:])
	if !bytes.Equal(digest[:checksumLength], priv.checksum[:]) {
		return errors.New("signify: invalid private key checksum")
	}
	return nil
}

func (priv *Private) crypt(password []byte) error {
	if !priv.IsEncrypted() {
		return nil
	}

	if string(priv.kdfAlgo[:]) != "BK" {
		return errors.New("signify: unsupported KDF algorithm " + string(priv.kdfAlgo[:]))
	}

	xorkey, err := bcrypt_pbkdf.Key(password, priv.salt[:], int(priv.kdfRounds), secretKeyLength)
	if err != nil {
		return err
	}

	for i := range priv.key[:] {
		priv.key[i] ^= xorkey[i]
	}

	err = priv.check()
	if err != nil {
		return err
	}

	return nil
}

func (priv *Private) sign(message []byte) (*Signature, error) {
	sig := &Signature{}
	copy(sig.pkAlgo[:], priv.keyAlgo[:])
	copy(sig.keyNum[:], priv.keyNum[:])
	edpriv := ed25519.PrivateKey(make([]byte, ed25519.PrivateKeySize))
	copy(edpriv[:], priv.key[:])

	signature := ed25519.Sign(edpriv, message)
	copy(sig.sig[:], signature)
	return sig, nil
}

func readPrivateKeyData(data []byte) (*Private, error) {
	buf := bytes.NewBuffer(data)
	priv := &Private{}

	_, err := buf.Read(priv.keyAlgo[:])
	if err != nil {
		return nil, err
	}

	_, err = buf.Read(priv.kdfAlgo[:])
	if err != nil {
		return nil, err
	}

	err = binary.Read(buf, binary.BigEndian, &priv.kdfRounds)
	if err != nil {
		return nil, err
	}

	_, err = buf.Read(priv.salt[:])
	if err != nil {
		return nil, err
	}

	_, err = buf.Read(priv.checksum[:])
	if err != nil {
		return nil, err
	}

	_, err = buf.Read(priv.keyNum[:])
	if err != nil {
		return nil, err
	}

	_, err = buf.Read(priv.key[:])
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func readPrivateKeyFile(data []byte) (*Private, error) {
	dat, err := readDataFileBytes(data)
	if err != nil {
		return nil, err
	}

	return readPrivateKeyData(dat.data)
}

func readPrivateKeyPath(path string) (*Private, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return readPrivateKeyFile(data)
}

func Sign(privatePath, messagePath, signaturePath string) error {
	priv, err := readPrivateKeyPath(privatePath)
	if err != nil {
		return err
	}

	if priv.IsEncrypted() {
		var passphrase []byte
		passphrase, err := PassphrasePrompt()
		if err != nil {
			return err
		}

		err = priv.crypt(passphrase)
		if err != nil {
			return err
		}
	}

	message, err := ioutil.ReadFile(messagePath)
	if err != nil {
		return err
	}

	if signaturePath == "" {
		signaturePath = messagePath + ".sig"
	}

	sig, err := priv.sign(message)
	if err != nil {
		return err
	}

	dat := &dataFile{}
	pubKeyPath := strings.TrimSuffix(privatePath, ".sec") + ".pub"
	dat.comment = "untrusted comment: verify with " + filepath.Base(pubKeyPath)
	dat.data = sig.Encode()
	err = ioutil.WriteFile(signaturePath, dat.Encode(), 0644)
	if err != nil {
		return err
	}

	return nil
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

func (pub *Public) verifyEd25519(message []byte, sig *Signature) error {
	if string(pub.keyAlgo[:]) != "Ed" {
		return errors.New("signify: not an Ed25519 public key")
	}

	if string(sig.pkAlgo[:]) != "Ed" {
		return errors.New("signify: not an Ed25519 signature")
	}

	if !bytes.Equal(pub.keyNum[:], sig.keyNum[:]) {
		return errors.New("signify: key number mismatch")
	}

	edpub := ed25519.PublicKey(pub.key[:])
	if !ed25519.Verify(edpub, message, sig.sig[:]) {
		return errors.New("signify: invalid signature")
	}
	return nil
}

func (pub *Public) verify(message []byte, sig *Signature) error {
	switch keyAlgo := string(pub.keyAlgo[:]); keyAlgo {
	case "Ed":
		return pub.verifyEd25519(message, sig)
	default:
		return errors.New("signify: unknown key algo " + keyAlgo)
	}
}

func readPublicKeyData(data []byte) (*Public, error) {
	if len(data) != (keyAlgoLength + keyNumLength + publicKeyLength) {
		return nil, fmt.Errorf("signify: invalid public key length %d", len(data))
	}

	pub := &Public{}
	didx := 0
	copy(pub.keyAlgo[:], data[:keyAlgoLength])
	didx += keyAlgoLength

	copy(pub.keyNum[:], data[didx:didx+keyNumLength])
	didx += keyNumLength

	copy(pub.key[:], data[didx:didx+publicKeyLength])

	return pub, nil
}

func readPublicKeyFile(data []byte) (*Public, error) {
	dat, err := readDataFileBytes(data)
	if err != nil {
		return nil, err
	}

	return readPublicKeyData(dat.data)
}

func readPublicKeyPath(path string) (*Public, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return readPublicKeyFile(data)
}

func Verify(publicPath, messagePath, signaturePath string) error {
	pub, err := readPublicKeyPath(publicPath)
	if err != nil {
		return err
	}

	message, err := ioutil.ReadFile(messagePath)
	if err != nil {
		return err
	}

	sig, err := readSignaturePath(signaturePath)
	if err != nil {
		return err
	}

	err = pub.verify(message, sig)
	if err != nil {
		return err
	}

	return nil
}
