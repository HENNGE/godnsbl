package godnsbl

import (
	"fmt"
	"net"
	"testing"
)

// Parallel for loop: https://play.golang.org/p/MVFwbmxbou
// http://www.golangpatterns.info/concurrency/parallel-for-loop

func TestReverseIP(t *testing.T) {
	t.Parallel()

	ip := net.IP{192, 168, 1, 1}

	r := Reverse(ip)

	if r != "1.1.168.192" {
		t.Errorf("Expected ip to equal 1.1.168.192, actual %s", r)
	}
}

func TestKnownIP(t *testing.T) {
	t.Parallel()

	for i := range Blacklists() {
		res := Lookup(Blacklists()[i], "127.0.0.2")
		fmt.Println(res.Results)
	}
}

func TestLookupParams(t *testing.T) {
	t.Parallel()

	blacklists := Blacklists()
	for i := range blacklists {
		res := Lookup(blacklists[i], "127.0.0.2")

		if res.List != blacklists[i] {
			t.Errorf("Expected %s, actual %s", blacklists[i], res.List)
		}

		if res.Host != "127.0.0.2" {
			t.Errorf("Expected 127.0.0.2, actual %s", res.Host)
		}
	}
}
