package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"go4.org/netipx"
)

// metadataAddress is the cloud instance metadata address. A workload that
// reaches it reads the node's credentials, so no exception can cover it.
const metadataAddress = "169.254.169.254"

var errException = errors.New("deny list exception refused")

// compiledPrefixes are the address ranges no sandbox can reach. They are
// platform policy. Changing the list requires a new build.
//
// Sources: RFC 1122 section 3.2.1.3 (loopback), RFC 1918 section 3 (private
// IPv4), RFC 3927 section 2.1 (IPv4 link-local, which carries the cloud
// metadata address), RFC 6598 section 7 (shared address space), RFC 4193
// section 3 (IPv6 unique local), RFC 4291 sections 2.4 and 2.5.6 (IPv6
// loopback, unspecified and link-local), RFC 6666 section 3 (IPv6 discard).
func compiledPrefixes() []string {
	return []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"100.64.0.0/10",
		"0.0.0.0/8",
		"::1/128",
		"::/128",
		"fc00::/7",
		"fe80::/10",
		"100::/64",
	}
}

// compiledHosts are names blocked by default: cloud metadata and public
// DNS-over-HTTPS resolvers. DoH should be generally blocked to prevent a
// workload from escaping DNS capture.
//
// These names were selected from:
// - https://github.com/curl/curl/wiki/DNS-over-HTTPS and
// - https://dnscrypt.info/public-servers/ on 2026-09-10.
func compiledHosts() []string {
	return []string{
		"metadata.google.internal",
		"metadata.goog",
		"instance-data",

		"dns.google",
		"dns.google.com",
		"dns64.dns.google",
		"8888.google",
		"cloudflare-dns.com",
		"security.cloudflare-dns.com",
		"family.cloudflare-dns.com",
		"mozilla.cloudflare-dns.com",
		"dns64.cloudflare-dns.com",
		"odoh.cloudflare-dns.com",
		"one.one.one.one",
		"dns.quad9.net",
		"dns9.quad9.net",
		"dns10.quad9.net",
		"dns11.quad9.net",
		"dns12.quad9.net",
		"doh.opendns.com",
		"doh.familyshield.opendns.com",
		"doh.umbrella.com",
		"doh.cleanbrowsing.org",
		"dns.nextdns.io",
		"doh.libredns.gr",
		"dns.alidns.com",
		"dns.pub",
		"doh.pub",
		"dns.sb",
		"doh.dns.sb",
		"resolver.dnscrypt.info",
		"dns.digitale-gesellschaft.ch",
		"dns.twnic.tw",
		"wikimedia-dns.org",
		"dns.switch.ch",
		"anycast.uncensoreddns.org",
		"dns.njal.la",
		"adguard-dns.com",
		"d.adguard-dns.com",
		"dns.adguard-dns.com",
		"family.adguard-dns.com",
		"unfiltered.adguard-dns.com",
		"freedns.controld.com",
		"dns.mullvad.net",
		"rethinkdns.com",
	}
}

// compiledSuffixes are name suffixes blocked for being DNS-over-HTTPS resolvers.
func compiledSuffixes() []string {
	return []string{
		".dns.nextdns.io",
		".adguard-dns.com",
		".freedns.controld.com",
		".dns.mullvad.net",
		".rethinkdns.com",
	}
}

// CompiledDigest produces a digest of the built-in deny list: the ranges, the
// host names and the name suffixes.
func CompiledDigest() string {
	sum := sha256.New()
	for _, list := range [][]string{compiledPrefixes(), compiledHosts(), compiledSuffixes()} {
		for _, entry := range list {
			sum.Write([]byte(entry))
			sum.Write([]byte{0})
		}
		sum.Write([]byte{1})
	}
	return "sha256:" + hex.EncodeToString(sum.Sum(nil))
}

// DenyList is the built-in deny list with the cluster's own ranges added and
// the operator's exceptions removed.
//
// Exceptions apply to addresses alone. A compiled host name stays denied
// whatever it resolves to, so the metadata names and the resolvers stay
// refused even inside an excepted range.
type DenyList struct {
	addrs      *netipx.IPSet
	hosts      map[string]struct{}
	suffixes   []string
	cluster    []netip.Prefix
	exceptions []netip.Prefix
}

// NewDenyList compiles the built-in deny list with clusterCIDRs added and
// exceptions removed. An exception covering the metadata address is refused.
func NewDenyList(clusterCIDRs, exceptions []netip.Prefix) (*DenyList, error) {
	var builder netipx.IPSetBuilder
	for _, raw := range compiledPrefixes() {
		builder.AddPrefix(netip.MustParsePrefix(raw))
	}
	for _, prefix := range clusterCIDRs {
		builder.AddPrefix(prefix.Masked())
	}
	metadata := netip.MustParseAddr(metadataAddress)
	for _, prefix := range exceptions {
		if prefix.Contains(metadata) {
			return nil, fmt.Errorf("%w: %s covers the cloud instance metadata address %s",
				errException, prefix, metadata)
		}
		builder.RemovePrefix(prefix.Masked())
	}
	set, err := builder.IPSet()
	if err != nil {
		return nil, fmt.Errorf("compile the deny list: %w", err)
	}

	hosts := make(map[string]struct{})
	for _, host := range compiledHosts() {
		hosts[host] = struct{}{}
	}
	return &DenyList{
		addrs:      set,
		hosts:      hosts,
		suffixes:   compiledSuffixes(),
		cluster:    append([]netip.Prefix(nil), clusterCIDRs...),
		exceptions: append([]netip.Prefix(nil), exceptions...),
	}, nil
}

// DeniesHost reports whether a host name or an IP literal is on the list.
func (d *DenyList) DeniesHost(host string) bool {
	host = NormalizeHost(host)
	if host == "" {
		return false
	}
	if _, ok := d.hosts[host]; ok {
		return true
	}
	for _, suffix := range d.suffixes {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return d.DeniesAddr(addr)
	}
	return false
}

// DeniesAddr reports whether an address is in a denied range. It unmaps an
// IPv4 address written in IPv4-mapped IPv6 form, so that spelling cannot
// sidestep an IPv4 range. An invalid address is denied.
func (d *DenyList) DeniesAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	return d.addrs.Contains(addr.Unmap().WithZone(""))
}

// Exceptions lists the excepted ranges, for the start-up announcement and
// the admin socket.
func (d *DenyList) Exceptions() []netip.Prefix {
	return append([]netip.Prefix(nil), d.exceptions...)
}

// ClusterCIDRs lists the cluster ranges covered by the deny list.
func (d *DenyList) ClusterCIDRs() []netip.Prefix {
	return append([]netip.Prefix(nil), d.cluster...)
}

// NormalizeHost lowercases a host and drops the root label. DNS names are
// case-insensitive (RFC 4343 section 1) and a name written with the root
// label is the same name (RFC 1034 section 3.1).
func NormalizeHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}
