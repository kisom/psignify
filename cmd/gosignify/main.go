package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"gitlab.com/kisom/crypted/signify"
)

func usage(w io.Writer) {
	fmt.Fprintf(w, `Usage: %s -V [-p pubkey] [-x sigfile] -m message
`, os.Args[0])
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

	var verify bool

	flag.StringVar(&pubKeyFile, "p", "", "public key file")
	flag.StringVar(&messageFile, "m", "", "message file")
	flag.StringVar(&signatureFile, "x", "", "signature file")
	flag.BoolVar(&verify, "V", false, "signature file")
	flag.Parse()

	if verify {
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
