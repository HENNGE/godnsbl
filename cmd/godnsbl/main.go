package main

import (
	"context"
	"fmt"
	"os"

	"github.com/HENNGE/godnsbl"
)

type RBLResult struct {
	Address string
	Listed  bool
	Text    string `json:",omitempty"`
}

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Please supply an IP address and RBL.")
		os.Exit(1)
	}

	ip := os.Args[1]
	rbl := os.Args[2]

	result, err := godnsbl.Lookup(context.Background(), rbl, ip)
	if err != nil {
		fmt.Println("Failed to lookup IP for RBL", err)
		return
	}

	fmt.Println("IP:", ip)
	fmt.Println("RBL:", rbl)
	fmt.Println("Listed:", result.Listed)
	if result.Text != "" {
		fmt.Println("Text:", result.Text)
	}
}
