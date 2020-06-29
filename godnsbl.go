// Package godnsbl lets you perform RBL lookups.
// A list of well know RBLs is provided.
// RBL = Real-time Blackhole List (https://en.wikipedia.org/wiki/DNSBL).
package godnsbl

import (
	"errors"
	"fmt"
	"net"
)

// Blacklists is the list of blackhole lists to check against.
// nolint:funlen
func Blacklists() []string {
	return []string{
		"aspews.ext.sorbs.net",
		"b.barracudacentral.org",
		"bl.deadbeef.com",
		"bl.emailbasura.org",
		"bl.spamcannibal.org",
		"bl.spamcop.net",
		"blackholes.five-ten-sg.com",
		"blacklist.woody.ch",
		"bogons.cymru.com",
		"cbl.abuseat.org",
		"cdl.anti-spam.org.cn",
		"combined.abuse.ch",
		"combined.rbl.msrbl.net",
		"db.wpbl.info",
		"dnsbl-1.uceprotect.net",
		"dnsbl-2.uceprotect.net",
		"dnsbl-3.uceprotect.net",
		"dnsbl.cyberlogic.net",
		"dnsbl.dronebl.org",
		"dnsbl.inps.de",
		"dnsbl.njabl.org",
		"dnsbl.sorbs.net",
		"drone.abuse.ch",
		"duinv.aupads.org",
		"dul.dnsbl.sorbs.net",
		"dul.ru",
		"dyna.spamrats.com",
		"dynip.rothen.com",
		"http.dnsbl.sorbs.net",
		"images.rbl.msrbl.net",
		"ips.backscatterer.org",
		"ix.dnsbl.manitu.net",
		"korea.services.net",
		"misc.dnsbl.sorbs.net",
		"noptr.spamrats.com",
		"ohps.dnsbl.net.au",
		"omrs.dnsbl.net.au",
		"orvedb.aupads.org",
		"osps.dnsbl.net.au",
		"osrs.dnsbl.net.au",
		"owfs.dnsbl.net.au",
		"owps.dnsbl.net.au",
		"phishing.rbl.msrbl.net",
		"probes.dnsbl.net.au",
		"proxy.bl.gweep.ca",
		"proxy.block.transip.nl",
		"psbl.surriel.com",
		"rdts.dnsbl.net.au",
		"relays.bl.gweep.ca",
		"relays.bl.kundenserver.de",
		"relays.nether.net",
		"residential.block.transip.nl",
		"ricn.dnsbl.net.au",
		"rmst.dnsbl.net.au",
		"short.rbl.jp",
		"smtp.dnsbl.sorbs.net",
		"socks.dnsbl.sorbs.net",
		"spam.abuse.ch",
		"spam.dnsbl.sorbs.net",
		"spam.rbl.msrbl.net",
		"spam.spamrats.com",
		"spamlist.or.kr",
		"spamrbl.imp.ch",
		"t3direct.dnsbl.net.au",
		"tor.dnsbl.sectoor.de",
		"torserver.tor.dnsbl.sectoor.de",
		"ubl.lashback.com",
		"ubl.unsubscore.com",
		"virbl.bit.nl",
		"virus.rbl.jp",
		"virus.rbl.msrbl.net",
		"web.dnsbl.sorbs.net",
		"wormrbl.imp.ch",
		"zen.spamhaus.org",
		"zombie.dnsbl.sorbs.net",
		"cidr.bl.mcafee.com",
	}
}

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
