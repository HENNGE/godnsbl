// Package godnsbl lets you perform RBL lookups.
// RBL = Real-time Blackhole List (https://en.wikipedia.org/wiki/DNSBL).
package godnsbl

import (
	"errors"
	"fmt"
	"net"
)

// Result holds the individual result of an IP lookup for an RBL search.
// nolint:maligned
type Result struct {
	// Listed indicates whether or not the IP was on the RBL
	Listed bool `json:"listed"`
	// RBL lists sometimes add extra information as a TXT record.
	// If any info is present, it will be stored here.
	Text string `json:"text"`
}

// Reverse the octets of a given IPv4 address
// '64.233.171.108' becomes '108.171.233.64'.
// If it's not an v4 IP, returns nil.
func Reverse(ip net.IP) net.IP {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}

	return net.IPv4(ip4[3], ip4[2], ip4[1], ip4[0])
}

func query(rbl string, ip net.IP) (*Result, error) {
	lookup := fmt.Sprintf("%s.%s", Reverse(ip).String(), rbl)

	res, err := net.LookupHost(lookup)
	if err != nil && !recordNotFound(err) { // If the record doesn't exists, the IP isn't blacklisted
		return nil, err
	}

	listed := false
	text := ""

	if len(res) > 0 {
		listed = true

		txt, err := net.LookupTXT(lookup)
		if err != nil && !isNonFatalDNSError(err) {
			return nil, fmt.Errorf("looking up TXT record: %w", err)
		}

		if len(txt) > 0 {
			text = txt[0]
		}
	}

	return &Result{
		Listed: listed,
		Text:   text,
	}, nil
}

func recordNotFound(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}

	return false
}

// false means the error is either a fatal DNS error, or not even a DNS error.
func isNonFatalDNSError(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.Temporary() || dnsErr.IsNotFound {
			return true
		}
	}

	return false
}

// Lookup performs the search and returns the RBLResults.
func Lookup(rblList string, rawIP string) (*Result, error) {
	ip := net.ParseIP(rawIP)
	ip4 := ip.To4()

	res, err := query(rblList, ip4)
	if err != nil {
		return nil, err
	}

	return res, nil
}
