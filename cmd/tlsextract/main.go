package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/wybiral/tlsextract"
)

func main() {
	args := os.Args[1:]
	if len(args) != 1 {
		fmt.Printf("USAGE:\n    tlsextract domain:port\n\n")
		fmt.Printf("VERSION:\n    %s\n\n", tlsextract.Version)
		os.Exit(0)
	}
	addr := args[0]
	// Use :443 as default port
	if !strings.Contains(addr, ":") {
		addr = addr + ":443"
	}
	// Get Metadata
	m, err := tlsextract.FromAddr(addr)
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
	// Encode to JSON
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	err = enc.Encode(m)
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
}
