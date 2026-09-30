package checks

import (
	"context"
	"time"
)

// Result is every finding for one target.
type Result struct {
	Target   Target    `json:"target"`
	Findings []Finding `json:"findings"`
}

// Run executes every check in order: DNS, TCP, TLS, HTTP.
func Run(ctx context.Context, t Target, o Options, now time.Time) Result {
	r := Result{Target: t}
	ips, fs := CheckDNS(ctx, t, o)
	r.Findings = append(r.Findings, fs...)
	addr, fs := CheckTCP(ctx, t, ips, o)
	r.Findings = append(r.Findings, fs...)
	tlsOK, fs := CheckTLS(ctx, t, addr, o, now)
	r.Findings = append(r.Findings, fs...)
	r.Findings = append(r.Findings, CheckHTTP(ctx, t, addr, tlsOK, o)...)
	return r
}
