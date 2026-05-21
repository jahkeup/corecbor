// SPDX-License-Identifier: Apache-2.0
// Copyright The corecbor Authors

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jahkeup/corecbor"
	"github.com/jahkeup/corecbor/rfc8949"
)

func main() {
	hexInput := flag.Bool("hex", false, "input is hex-encoded text")
	compact := flag.Bool("compact", false, "no whitespace")
	sequence := flag.Bool("sequence", false, "treat as CBOR sequence")
	flag.Parse()

	var opts []corecbor.DiagnosticOption
	if *compact {
		opts = append(opts, corecbor.DiagCompact())
	}

	data, err := readInput(flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "cbor-diag: %v\n", err)
		os.Exit(1)
	}

	if *hexInput {
		cleaned := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
				return -1
			}
			return r
		}, string(data))
		data, err = hex.DecodeString(cleaned)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cbor-diag: invalid hex: %v\n", err)
			os.Exit(1)
		}
	}

	if *sequence {
		decOpts := rfc8949.DecodeOpts{}
		for len(data) > 0 {
			v, n, decErr := rfc8949.Decode(data, decOpts)
			if decErr != nil {
				fmt.Fprintf(os.Stderr, "cbor-diag: %v\n", decErr)
				os.Exit(1)
			}
			fmt.Println(corecbor.DiagnosticValue(v, opts...))
			data = data[n:]
		}
	} else {
		s, diagErr := corecbor.Diagnostic(data, opts...)
		if diagErr != nil {
			fmt.Fprintf(os.Stderr, "cbor-diag: %v\n", diagErr)
			os.Exit(1)
		}
		fmt.Println(s)
	}
}

func readInput(args []string) ([]byte, error) {
	if len(args) == 0 {
		return io.ReadAll(os.Stdin)
	}
	var all []byte
	for _, name := range args {
		b, err := os.ReadFile(name)
		if err != nil {
			return nil, err
		}
		all = append(all, b...)
	}
	return all, nil
}
