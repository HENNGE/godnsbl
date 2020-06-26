package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/HENNGE/godnsbl"
)

func main() {

	if len(os.Args) != 2 {
		fmt.Println("Please supply a domain name or IP address.")
		os.Exit(1)
	}

	ip := os.Args[1]

	wg := &sync.WaitGroup{}
	blacklists := godnsbl.Blacklists()
	results := make([]godnsbl.Result, 0, len(blacklists))
	for i, source := range blacklists {
		wg.Add(1)
		go func(i int, source string) {
			defer wg.Done()
			rbl := godnsbl.Lookup(source, ip)
			if len(rbl.Results) == 0 {
				results[i] = godnsbl.Result{}
			} else {
				results[i] = rbl.Results[0]
			}
		}(i, source)
	}

	wg.Wait()

	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(&results); err != nil {
		log.Println(err)
	}
}
