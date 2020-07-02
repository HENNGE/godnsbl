package godnsbl

import (
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
