package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/HENNGE/godnsbl"
)

type RBLResult struct {
	Address string
	Listed  bool
	Text    string `json:",omitempty"`
	Error   string `json:",omitempty"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Please supply an IP address.")
		os.Exit(1)
	}

	ip := os.Args[1]

	wg := &sync.WaitGroup{}
	blacklists := godnsbl.Blacklists()
	results := make([]RBLResult, len(blacklists))
	for i, source := range blacklists {
		wg.Add(1)
		go func(i int, list string) {
			defer wg.Done()
			result, err := godnsbl.Lookup(list, ip)
			if err != nil {
				results[i] = RBLResult{
					Address: ip,
					Error:   err.Error(),
				}
				return
			}

			results[i] = RBLResult{
				Address: ip,
				Listed:  result.Listed,
				Text:    result.Text,
			}
		}(i, source)
	}

	wg.Wait()

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "	")
	if err := enc.Encode(&results); err != nil {
		log.Println(err)
	}
}
