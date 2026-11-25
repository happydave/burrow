package burrow

// Outer overhead of one data packet: DATA_V2 (spec notes 11.8) plus UDP
// and the outer IP header.
const (
	dataOverhead = 25
	udpHeader    = 8
	ipv4Header   = 20
	ipv6Header   = 40
)

// DefaultMSSFix is the man page's default, with mtu semantics: the whole
// outer IP packet stays within it (spec notes 18.2).
const DefaultMSSFix = 1492

// linkMTU is the userspace stack's MTU: the tunnel MTU (1500 when none),
// lowered so an encapsulated packet fits mssfix. wireguard-go's netstack
// cannot set a TCP MSS, so the MTU carries the bound, and the MSS
// follows from it. With payload set, mssfix bounds the UDP payload rather
// than the outer packet (spec notes 18.2). mssfix 0 disables the bound.
func linkMTU(tunMTU, mssfix int, payload, ipv6Outer bool) int {
	if tunMTU == 0 {
		tunMTU = 1500
	}
	if mssfix <= 0 {
		return tunMTU
	}
	if payload {
		return min(tunMTU, mssfix-dataOverhead)
	}
	outer := ipv4Header
	if ipv6Outer {
		outer = ipv6Header
	}
	return min(tunMTU, mssfix-outer-udpHeader-dataOverhead)
}
