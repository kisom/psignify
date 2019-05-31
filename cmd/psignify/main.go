package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/kisom/psignify/signify"
)

func usage(w io.Writer) {
	fmt.Fprintf(w, `
Usage: %s -V [-p pubkey] [-x sigfile] -m message
       %s -G [-n] -p keyname
`, os.Args[0], os.Args[0])
}

func init() {
	flag.Usage = func() {
		usage(os.Stdout)
		os.Exit(0)
	}
}

func main() {
	var pubKeyFile string
	var messageFile string
	var signatureFile string
	var noPass bool

	var generate bool
	var verify bool

	flag.StringVar(&messageFile, "m", "", "message file")
	flag.BoolVar(&noPass, "n", false, "use an empty passphrase")
	flag.StringVar(&pubKeyFile, "p", "", "public key file")
	flag.StringVar(&signatureFile, "x", "", "signature file")

	flag.BoolVar(&generate, "G", false, "generate keypair")
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
	} else if verify {
		err := signify.Verify(pubKeyFile, messageFile, signatureFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: invalid signature\n", messageFile)
			os.Exit(1)
		}

		fmt.Printf("%s: OK\n", messageFile)
	} else {
		usage(os.Stderr)
		os.Exit(1)
	}
}
