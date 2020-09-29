package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/wybiral/tlsextract"
)

func checkErr(err error) {
	if err == nil {
		return
	}

	fmt.Println("ERROR:", err)
	os.Exit(1)
}

func main() {
	args := os.Args[1:]
	if len(args) != 1 {
		fmt.Printf("USAGE:\n    tlsextract < host:port | url >\n\n")
		fmt.Printf("VERSION:\n    %s\n\n", tlsextract.Version)
		os.Exit(0)
	}

	parsedURL, err := url.Parse(args[0])
	checkErr(err)

	if parsedURL.Host == "" {
		if parsedURL.Path == "" {
			parsedURL.Host = parsedURL.Scheme + ":" + parsedURL.Opaque
		} else {
			parsedURL.Host = parsedURL.Path
		}
	}

	if parsedURL.Port() == "" {
		parsedURL.Host += ":443"
	}

	// Get Metadata
	m, err := tlsextract.FromAddr(parsedURL.Host)
	checkErr(err)

	// Encode to JSON
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	checkErr(enc.Encode(m))
}
