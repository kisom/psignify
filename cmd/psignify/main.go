package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/kisom/psignify/crypto"
	"github.com/kisom/psignify/signify"
)

func usage(w io.Writer) {
	fmt.Fprintf(w, `
Usage: %s -S -s seckey -m message [-x sigfile]
       %s -V -p pubkey [-x sigfile] -m message
       %s -G [-n] -p keyname
       %s -E -p pubkey -m message [-c encrypted]
       %s -D -s privkey -c encrypted -m message
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}

func init() {
	flag.Usage = func() {
		usage(os.Stdout)
		os.Exit(0)
	}
}

func main() {
	var pubKeyFile string
	var privKeyFile string
	var messageFile string
	var encryptedFile string
	var signatureFile string
	var noPass bool

	var decrypt bool
	var encrypt bool
	var generate bool
	var sign bool
	var verify bool

	flag.StringVar(&encryptedFile, "c", "", "encrypted file")
	flag.StringVar(&messageFile, "m", "", "message file")
	flag.BoolVar(&noPass, "n", false, "use an empty passphrase")
	flag.StringVar(&pubKeyFile, "p", "", "public key file")
	flag.StringVar(&privKeyFile, "s", "", "private key file")
	flag.StringVar(&signatureFile, "x", "", "signature file")

	flag.BoolVar(&decrypt, "D", false, "decrypt a message")
	flag.BoolVar(&encrypt, "E", false, "encrypt a message")
	flag.BoolVar(&generate, "G", false, "generate keypair")
	flag.BoolVar(&sign, "S", false, "sign a file")
	flag.BoolVar(&verify, "V", false, "signature file")
	flag.Parse()

	if generate {
		var passphrase []byte
		var err error

		if pubKeyFile == "" {
			fmt.Fprintln(os.Stderr, "Please provide the base name for the keypair.")
			os.Exit(1)
		}

		if !noPass {
			passphrase, err = signify.PassphrasePrompt(true)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err)
				os.Exit(1)
			}
		}

		err = signify.GenerateKey(pubKeyFile, passphrase, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to generate keypair: %s\n", err)
			os.Exit(1)
		}
	} else if sign {
		if privKeyFile == "" || messageFile == "" {
			fmt.Fprintln(os.Stderr, "Signing requires a message and private key.")
			os.Exit(1)
		}

		err := signify.Sign(privKeyFile, messageFile, signatureFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Signing %s failed: %s\n", messageFile, err)
			os.Exit(1)
		}
	} else if verify {
		err := signify.Verify(pubKeyFile, messageFile, signatureFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: invalid signature\n", messageFile)
			os.Exit(1)
		}

		fmt.Printf("%s: OK\n", messageFile)
	} else if encrypt {
		err := crypto.Seal(pubKeyFile, messageFile, encryptedFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}

		fmt.Printf("%s: OK\n", messageFile)
	} else if decrypt {
		err := crypto.Open(privKeyFile, encryptedFile, messageFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}

		fmt.Printf("%s: OK\n", encryptedFile)
	} else {
		usage(os.Stderr)
		os.Exit(1)
	}
}
