// Package resolvconf parses /etc/resolv.conf, best effort.
package resolvconf

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
)

// Path is the file read by Load.
const Path = "/etc/resolv.conf"

// Config is the subset of resolv.conf that explains DNS behaviour.
type Config struct {
	Nameservers []string `json:"nameservers"`
	Search      []string `json:"search"`
	Ndots       int      `json:"ndots"`
	Options     []string `json:"options"`
}

// Load reads Path. A missing file returns ok=false, not an error: Windows
// and some minimal containers have none.
func Load() (Config, bool) {
	f, err := os.Open(Path)
	if err != nil {
		return Config{}, false
	}
	defer f.Close()
	return Parse(f), true
}

// Parse reads resolv.conf syntax. Unknown lines are ignored.
func Parse(r io.Reader) Config {
	c := Config{Ndots: 1}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "nameserver":
			c.Nameservers = append(c.Nameservers, f[1])
		case "search", "domain":
			c.Search = append([]string{}, f[1:]...) // last one wins, like glibc
		case "options":
			for _, o := range f[1:] {
				if v, ok := strings.CutPrefix(o, "ndots:"); ok {
					if n, err := strconv.Atoi(v); err == nil {
						c.Ndots = min(n, 15)
					}
					continue
				}
				c.Options = append(c.Options, o)
			}
		}
	}
	return c
}

// ExtraLookups is how many search-domain lookups happen before the name
// is tried as-is, per record type.
func (c Config) ExtraLookups(host string) int {
	if strings.HasSuffix(host, ".") {
		return 0
	}
	if strings.Count(host, ".") >= c.Ndots {
		return 0
	}
	return len(c.Search)
}
