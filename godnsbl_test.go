package godnsbl

import (
	"fmt"
	"net"
	"testing"
)

func TestReverseIP(t *testing.T) {
	t.Parallel()

	ip := net.IPv4(192, 168, 1, 1)

	actual := Reverse(ip)

	expected := net.IPv4(1, 1, 168, 192)
	if !actual.Equal(expected) {
		t.Errorf("Expected ip to equal %s, actual %s", expected, actual)
	}
}

func TestKnownIP(t *testing.T) {
	t.Parallel()

	for i := range Blacklists() {
		res, err := Lookup(Blacklists()[i], "127.0.0.2")
		fmt.Println(res, err)
	}
}
