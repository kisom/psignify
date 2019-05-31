package signify

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/dchest/bcrypt_pbkdf"
	"github.com/kisom/psignify/signify/edwards25519"
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
	kdfRounds       = 42
)

// PassphrasePrompt prompts the user for a passphrase. If confirm is true, the
// passphrase will be confirmed.
var PassphrasePrompt = func(confirm bool) ([]byte, error) {
	fmt.Printf("Password: ")
	passphrase, err := terminal.ReadPassword(0)
	if err != nil {
		return nil, err
	}

	fmt.Println()
	if !confirm {
		return passphrase, nil
	}

	fmt.Printf("Confirm password: ")
	confirmPassphrase, err := terminal.ReadPassword(0)
	if err != nil {
		return nil, err
	}
	defer zero(&confirmPassphrase)
	fmt.Println()

	if !bytes.Equal(passphrase, confirmPassphrase) {
		return nil, errors.New("passphrases don't match")
	}

	return passphrase, nil
}

// Private is a signify private key.
type Private struct {
	keyAlgo   [keyAlgoLength]uint8
	kdfAlgo   [kdfAlgoLength]uint8
	kdfRounds uint32
	salt      [saltLength]uint8
	checksum  [checksumLength]uint8
	keyNum    [keyNumLength]uint8
	key       [secretKeyLength]uint8
}

func (priv *Private) encode() []byte {
	buf := &bytes.Buffer{}
	buf.Write(priv.keyAlgo[:])
	buf.Write(priv.kdfAlgo[:])
	binary.Write(buf, binary.BigEndian, priv.kdfRounds)
	buf.Write(priv.salt[:])
	buf.Write(priv.checksum[:])
	buf.Write(priv.keyNum[:])
	buf.Write(priv.key[:])
	return buf.Bytes()
}

// IsEncrypted returns true if the key is passphrase-protected.
func (priv *Private) IsEncrypted() bool {
	return priv.kdfRounds > 0
}

// check verifies that the key has been decrypted properly.
func (priv *Private) check() error {
	digest := sha512.Sum512(priv.key[:])
	if !bytes.Equal(digest[:checksumLength], priv.checksum[:]) {
		return errors.New("signify: invalid private key checksum")
	}
	return nil
}

func (priv *Private) decrypt(password []byte) error {
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

// Sign signs the message and outputs a well-formed signify signature.
func Sign(privatePath, messagePath, signaturePath string) error {
	if signaturePath == "" {
		signaturePath = messagePath + ".sig"
	}

	priv, err := readPrivateKeyPath(privatePath)
	if err != nil {
		return err
	}

	if priv.IsEncrypted() {
		var passphrase []byte
		passphrase, err := PassphrasePrompt(false)
		if err != nil {
			return err
		}
		defer zero(&passphrase)

		err = priv.decrypt(passphrase)
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

	pubKeyPath := strings.TrimSuffix(privatePath, ".sec") + ".pub"
	comment := "untrusted comment: verify with " + filepath.Base(pubKeyPath)
	err = writeDataFile(signaturePath, comment, sig.encode())
	if err != nil {
		return err
	}

	return nil
}

func (priv *Private) ToBox() (*[32]byte, error) {
	err := priv.check()
	if err != nil {
		var passphrase []byte
		passphrase, err = PassphrasePrompt(false)
		if err != nil {
			return nil, err
		}

		err = priv.decrypt(passphrase)
		if err != nil {
			return nil, err
		}
	}

	var sboxKey [32]byte
	digest := sha512.Sum512(priv.key[:32])
	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64
	copy(sboxKey[:], digest[:])
	defer zero64(&digest)
	return &sboxKey, nil
}

// Public is a Signify public key.
type Public struct {
	keyAlgo [keyAlgoLength]uint8
	keyNum  [keyNumLength]uint8
	key     [publicKeyLength]byte
}

func (pub *Public) encode() []byte {
	buf := &bytes.Buffer{}
	buf.Write(pub.keyAlgo[:])
	buf.Write(pub.keyNum[:])
	buf.Write(pub.key[:])
	return buf.Bytes()
}

func (pub *Public) verifyEd25519(message []byte, sig *Signature) error {
	if string(pub.keyAlgo[:]) != "Ed" {
		return errors.New("signify: not an Ed25519 public key")
	}

	if string(sig.pkAlgo[:]) != "Ed" {
		return errors.New("signify: not an Ed25519 signature (" + string(sig.pkAlgo[:]) + ")")
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

func (pub *Public) ToBox() (*[32]byte, error) {
	var A = &edwards25519.ExtendedGroupElement{}
	var oneMinusY = &edwards25519.FieldElement{}
	var x = &edwards25519.FieldElement{}

	edpub := [32]byte{}
	copy(edpub[:], pub.key[:])

	if !A.FromBytes(&edpub) {
		return nil, errors.New("signify: invalid public key")
	}

	edwards25519.FeOne(oneMinusY)
	edwards25519.FeSub(oneMinusY, oneMinusY, &A.Y)
	edwards25519.FeOne(x)
	edwards25519.FeAdd(x, x, &A.Y)
	edwards25519.FeInvert(oneMinusY, oneMinusY)
	edwards25519.FeMul(x, x, oneMinusY)
	edwards25519.FeToBytes(&edpub, x)

	return &edpub, nil
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

// Verify checks the signature on a message.
func Verify(publicPath, messagePath, signaturePath string) error {
	if signaturePath == "" {
		signaturePath = messagePath + ".sig"
	}

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

// GenerateOptions control the generation of private keys.
type GenerateOptions struct {
	Rounds int
}

var defaultOptions = GenerateOptions{Rounds: 42}

func generateKeypair(passphrase []byte, opts *GenerateOptions) (*Private, *Public, error) {
	if opts == nil {
		opts = &defaultOptions
	}

	edpub, edpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	priv := &Private{}
	copy(priv.keyAlgo[:], []byte("Ed"))
	copy(priv.kdfAlgo[:], []byte("BK"))

	if len(passphrase) == 0 {
		priv.kdfRounds = 0
	} else {
		priv.kdfRounds = uint32(opts.Rounds)
	}

	_, err = rand.Read(priv.salt[:])
	if err != nil {
		return nil, nil, err
	}

	_, err = rand.Read(priv.keyNum[:])
	if err != nil {
		return nil, nil, err
	}

	digest := sha512.Sum512(edpriv[:])
	copy(priv.checksum[:], digest[:])
	copy(priv.key[:], edpriv[:])

	if len(passphrase) != 0 {
		xorkey, err := bcrypt_pbkdf.Key(passphrase, priv.salt[:], int(priv.kdfRounds), secretKeyLength)
		if err != nil {
			return nil, nil, err
		}

		for i := range priv.key[:] {
			priv.key[i] ^= xorkey[i]
		}
	}

	pub := &Public{}
	copy(pub.keyAlgo[:], priv.keyAlgo[:])
	copy(pub.keyNum[:], priv.keyNum[:])
	copy(pub.key[:], edpub[:])

	return priv, pub, nil
}

// GenerateKey generates a new signify keypair under keypath.sec and
// keypath.pub. If passphrase is provided, the private key is
// encrypted. If opts is nil, a set of sane defaults is provided.
func GenerateKey(keyPath string, passphrase []byte, opts *GenerateOptions) error {
	priv, pub, err := generateKeypair(passphrase, opts)
	if err != nil {
		return err
	}

	err = writeDataFile(keyPath+".sec", "untrusted comment: signify private key", priv.encode())
	if err != nil {
		return err
	}

	err = writeDataFile(keyPath+".pub", "untrusted comment: signify public key", pub.encode())
	if err != nil {
		return err
	}

	return nil
}
