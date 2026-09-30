package checks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Slow is when a system lookup starts to look suspicious.
const Slow = 300 * time.Millisecond

// answer is one resolver's reply to an A query.
type answer struct {
	resolver Resolver
	rcode    int
	ips      []string
	ttl      uint32
	cname    string
	rtt      time.Duration
	err      error
}

// CheckDNS questions the resolver. It returns the addresses the system
// resolver gave, which the other checks use.
func CheckDNS(ctx context.Context, t Target, o Options) ([]string, []Finding) {
	var fs []Finding
	add := func(check, detail string, sev Severity, d time.Duration) {
		fs = append(fs, Finding{Suspect: DNS, Check: check, Detail: detail, Severity: sev, Duration: d})
	}
	if t.IsIP {
		add("lookup", "you gave me an IP address, so no lookup was needed", Info, 0)
		return []string{t.Host}, fs
	}

	if rc := o.ResolvConf; rc != nil {
		desc := []string{}
		if len(rc.Nameservers) > 0 {
			desc = append(desc, "nameserver "+strings.Join(rc.Nameservers, " "))
		}
		if len(rc.Search) > 0 {
			desc = append(desc, "search "+strings.Join(rc.Search, " "))
		}
		desc = append(desc, fmt.Sprintf("ndots:%d", rc.Ndots))
		add("resolv.conf", strings.Join(desc, ", "), OK, 0)
		if n := rc.ExtraLookups(t.Host); n > 0 && rc.Ndots > 1 {
			add("ndots", fmt.Sprintf("ndots:%d with %d search domains: %s tries %d wrong names before the real one. Add a trailing dot or lower ndots",
				rc.Ndots, len(rc.Search), t.Host, n), Warn, 0)
		}
	}

	// The lookup the application would actually do.
	start := time.Now()
	lctx, cancel := context.WithTimeout(ctx, o.Timeout)
	addrs, err := o.system().LookupIPAddr(lctx, t.Host)
	cancel()
	took := time.Since(start)
	var ips []string
	if err != nil {
		add("system lookup", describeLookupErr(t.Host, err, o.Timeout), Fail, took)
	} else {
		for _, a := range addrs {
			ips = append(ips, a.IP.String())
		}
		sortIPs(ips)
		sev := OK
		if took > Slow {
			sev = Warn
		}
		add("system lookup", t.Host+" -> "+strings.Join(ips, ", "), sev, took)
	}

	// Ask each resolver directly, in parallel.
	answers := make([]answer, len(o.Resolvers))
	var wg sync.WaitGroup
	for i, r := range o.Resolvers {
		wg.Add(1)
		go func(i int, r Resolver) {
			defer wg.Done()
			answers[i] = query(ctx, r, t.Host, dns.TypeA, true, o.Timeout)
		}(i, r)
	}
	wg.Wait()
	for _, a := range answers {
		f := describeAnswer(a)
		// The first nameserver failing while the lookup still worked means
		// the resolver library fell back to the next one: slow, not broken.
		if f.Severity == Fail && a.err != nil && err == nil && strings.HasPrefix(a.resolver.Name, "system") {
			f.Severity = Warn
			f.Detail += ". Lookups fall back to the next nameserver, after a delay"
		}
		fs = append(fs, f)
	}
	fs = append(fs, compareAnswers(answers)...)

	if !o.NoAuth {
		fs = append(fs, authoritative(ctx, t.Host, ips, answers, o)...)
	}
	return ips, fs
}

func query(ctx context.Context, r Resolver, host string, qtype uint16, recurse bool, timeout time.Duration) answer {
	a := answer{resolver: r, rcode: -1}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), qtype)
	m.RecursionDesired = recurse
	c := &dns.Client{Timeout: timeout}
	qctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resp, rtt, err := c.ExchangeContext(qctx, m, r.Addr)
	if err == nil && resp.Truncated {
		c.Net = "tcp"
		resp, rtt, err = c.ExchangeContext(qctx, m, r.Addr)
	}
	a.rtt = rtt
	if err != nil {
		a.err = err
		return a
	}
	a.rcode = resp.Rcode
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			a.ips = append(a.ips, v.A.String())
			a.ttl = v.Hdr.Ttl
		case *dns.AAAA:
			a.ips = append(a.ips, v.AAAA.String())
			a.ttl = v.Hdr.Ttl
		case *dns.CNAME:
			if a.cname == "" {
				a.cname = strings.TrimSuffix(v.Target, ".")
			}
		}
	}
	sortIPs(a.ips)
	return a
}

func describeAnswer(a answer) Finding {
	f := Finding{Suspect: DNS, Check: a.resolver.Name, Duration: a.rtt}
	isSystem := strings.HasPrefix(a.resolver.Name, "system")
	switch {
	case a.err != nil:
		f.Severity = Info
		if isSystem {
			f.Severity = Fail
		}
		f.Detail = "no answer: " + shortNetErr(a.err)
		if !isSystem {
			f.Detail += " (blocked by a firewall or proxy, which is also a DNS problem)"
		}
	case a.rcode == dns.RcodeNameError:
		f.Severity, f.Detail = Fail, "NXDOMAIN: this resolver says the name does not exist"
	case a.rcode == dns.RcodeServerFailure:
		f.Severity, f.Detail = Fail, "SERVFAIL: the resolver gave up (often DNSSEC or a dead authoritative server)"
	case a.rcode == dns.RcodeRefused:
		f.Severity, f.Detail = Warn, "REFUSED: this resolver will not answer you"
	case a.rcode != dns.RcodeSuccess:
		f.Severity, f.Detail = Warn, "rcode "+dns.RcodeToString[a.rcode]
	case len(a.ips) == 0:
		f.Severity, f.Detail = Warn, "NOERROR but no A records (NODATA)"
		if a.cname != "" {
			f.Detail += ", CNAME " + a.cname
		}
	default:
		f.Detail = fmt.Sprintf("%s (TTL %d)", strings.Join(a.ips, ", "), a.ttl)
		if a.cname != "" {
			f.Detail = "CNAME " + a.cname + " -> " + f.Detail
		}
	}
	return f
}

// compareAnswers flags resolvers that disagree about whether the name exists.
// Different IPs are normal for CDNs, so that is only informational.
func compareAnswers(as []answer) []Finding {
	var withIPs, nx []string
	sets := map[string]bool{}
	for _, a := range as {
		switch {
		case a.err == nil && a.rcode == dns.RcodeSuccess && len(a.ips) > 0:
			withIPs = append(withIPs, a.resolver.Name)
			sets[strings.Join(a.ips, ",")] = true
		case a.err == nil && a.rcode == dns.RcodeNameError:
			nx = append(nx, a.resolver.Name)
		}
	}
	switch {
	case len(withIPs) > 0 && len(nx) > 0:
		return []Finding{{Suspect: DNS, Check: "agreement", Severity: Warn,
			Detail: fmt.Sprintf("%s say the name exists, %s say it does not: split horizon, or a record that changed recently",
				strings.Join(withIPs, " and "), strings.Join(nx, " and "))}}
	case len(sets) > 1:
		return []Finding{{Suspect: DNS, Check: "agreement", Severity: Info,
			Detail: "resolvers returned different addresses: normal for a CDN, suspicious otherwise"}}
	}
	return nil
}

// authoritative finds the zone's name server and asks it without recursion.
func authoritative(ctx context.Context, host string, systemIPs []string, as []answer, o Options) []Finding {
	var via *Resolver
	for _, a := range as {
		if a.err == nil {
			r := a.resolver
			via = &r
			break
		}
	}
	if via == nil {
		return []Finding{{Suspect: DNS, Check: "authoritative", Severity: Info, Detail: "skipped: no resolver answered, so the name server could not be found"}}
	}
	nsName := ""
	for zone := host; strings.Contains(zone, ".") && nsName == ""; {
		a := queryNS(ctx, *via, zone, o.Timeout)
		if a != "" {
			nsName = a
			break
		}
		_, parent, _ := strings.Cut(zone, ".")
		zone = parent
	}
	if nsName == "" {
		return []Finding{{Suspect: DNS, Check: "authoritative", Severity: Info, Detail: "could not find a name server for this zone"}}
	}
	nsAddr := query(ctx, *via, nsName, dns.TypeA, true, o.Timeout)
	if len(nsAddr.ips) == 0 {
		return []Finding{{Suspect: DNS, Check: "authoritative", Severity: Warn, Detail: "name server " + nsName + " has no address. Lame delegation?"}}
	}
	r := Resolver{Name: "authoritative", Addr: net.JoinHostPort(nsAddr.ips[0], o.AuthPort)}
	a := query(ctx, r, host, dns.TypeA, false, o.Timeout)
	f := describeAnswer(a)
	f.Detail += " from " + nsName
	fs := []Finding{f}
	if len(a.ips) > 0 && len(systemIPs) > 0 && !overlaps(a.ips, systemIPs) {
		fs = append(fs, Finding{Suspect: DNS, Check: "freshness", Severity: Info,
			Detail: "the system resolver's answer differs from the authoritative one: a CDN, or a cache that has not caught up"})
	}
	return fs
}

func queryNS(ctx context.Context, r Resolver, zone string, timeout time.Duration) string {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeNS)
	c := &dns.Client{Timeout: timeout}
	qctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resp, _, err := c.ExchangeContext(qctx, m, r.Addr)
	if err != nil {
		return ""
	}
	var names []string
	for _, rr := range resp.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			names = append(names, strings.TrimSuffix(ns.Ns, "."))
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

func describeLookupErr(host string, err error, timeout time.Duration) string {
	var de *net.DNSError
	if errors.As(err, &de) {
		switch {
		case de.IsNotFound:
			return host + " does not exist (NXDOMAIN or no records)"
		case de.IsTimeout || errors.Is(err, context.DeadlineExceeded):
			return fmt.Sprintf("timed out after %s", timeout)
		}
		return de.Err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Sprintf("timed out after %s", timeout)
	}
	return err.Error()
}

func shortNetErr(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded) {
		return "timed out"
	}
	s := err.Error()
	if strings.Contains(s, "connection refused") {
		return "connection refused"
	}
	return s
}

func overlaps(a, b []string) bool {
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	for _, y := range b {
		if set[y] {
			return true
		}
	}
	return false
}

// sortIPs puts IPv4 before IPv6, then sorts lexically, so output is stable.
func sortIPs(ips []string) {
	sort.Slice(ips, func(i, j int) bool {
		a4, b4 := !strings.Contains(ips[i], ":"), !strings.Contains(ips[j], ":")
		if a4 != b4 {
			return a4
		}
		return ips[i] < ips[j]
	})
}
