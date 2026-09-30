// Command its-always-dns runs real network diagnostics, narrates them as a
// detective case, and always concludes that it was DNS.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/spf13/cobra"

	"github.com/khimananda/its-always-dns/internal/checks"
	"github.com/khimananda/its-always-dns/internal/detective"
	"github.com/khimananda/its-always-dns/internal/phrases"
	"github.com/khimananda/its-always-dns/internal/render"
)

// Set by GoReleaser. go install builds fall back to the module version.
var version = "dev"

func init() {
	if version != "dev" {
		return
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = strings.TrimPrefix(bi.Main.Version, "v")
	}
}

// ExitDNS is the exit code of every narrative run. Port 53, naturally.
const ExitDNS = 53

// exitError carries an exit code out of cobra.
type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit %d", e.code) }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	err := newRoot(os.Stdout, checks.Defaults).ExecuteContext(ctx)
	var ee exitError
	switch {
	case errors.As(err, &ee):
		os.Exit(ee.code)
	case err != nil:
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type flags struct {
	serious   bool
	json      bool
	port      int
	timeout   time.Duration
	resolvers []string
	seed      string
	noTiming  bool
	noColor   bool
	noAuth    bool
}

// defaultsFunc builds check options; tests replace it.
type defaultsFunc func(timeout time.Duration, extra []string) checks.Options

func newRoot(stdout io.Writer, defaults defaultsFunc) *cobra.Command {
	var f flags
	cmd := &cobra.Command{
		Use:   "its-always-dns HOST|URL",
		Short: "Network diagnostics that always conclude it was DNS",
		Long: `Runs real checks against a host: resolv.conf, the system lookup, direct
queries to several resolvers and the authoritative name server, a TCP
connect, the TLS certificate and an HTTP request. Then it narrates them
as a detective case and concludes that it was DNS.

The evidence section always says what actually broke.`,
		Example: `  its-always-dns api.example.com
  its-always-dns https://example.com/health
  its-always-dns db.internal:5432
  its-always-dns example.com --serious        # exit 0 when healthy, 1 on failure
  its-always-dns example.com --json | jq .actual_culprit`,
		Version:       version,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return investigate(cmd.Context(), stdout, args[0], f, defaults)
		},
	}
	fl := cmd.Flags()
	fl.BoolVar(&f.serious, "serious", false, "plain report; exit 0 when nothing failed, 1 otherwise")
	fl.BoolVar(&f.json, "json", false, "print the case as JSON")
	fl.IntVarP(&f.port, "port", "p", 0, "port to test (default from the URL, else 443)")
	fl.DurationVar(&f.timeout, "timeout", 3*time.Second, "timeout for each check")
	fl.StringSliceVar(&f.resolvers, "resolver", nil, "extra resolver to question, ip or ip:port (repeatable)")
	fl.StringVar(&f.seed, "seed", "", "seed for the case number and title (default: the host)")
	fl.BoolVar(&f.noTiming, "no-timing", false, "hide durations, for reproducible output")
	fl.BoolVar(&f.noColor, "no-color", false, "disable colors (NO_COLOR is also honoured)")
	fl.BoolVar(&f.noAuth, "no-authoritative", false, "skip the authoritative name server lookup")

	cmd.AddCommand(&cobra.Command{
		Use:   "haiku",
		Short: "Print the haiku",
		Args:  cobra.NoArgs,
		Run:   func(*cobra.Command, []string) { fmt.Fprintln(stdout, phrases.Haiku) },
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "why",
		Short: "Explain one real way DNS breaks",
		Long:  "Explain one real way DNS breaks. Run it again for another. Use --all to list them.",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			all, _ := c.Flags().GetBool("all")
			lessons := phrases.Lessons()
			if all {
				for _, l := range lessons {
					fmt.Fprintf(stdout, "%s\n  %s\n\n", l.Title, l.Text)
				}
				return nil
			}
			l := lessons[int(time.Now().UnixNano()%int64(len(lessons)))]
			fmt.Fprintf(stdout, "%s\n  %s\n", l.Title, l.Text)
			return nil
		},
	})
	cmd.Commands()[len(cmd.Commands())-1].Flags().Bool("all", false, "list every lesson")
	return cmd
}

func investigate(ctx context.Context, stdout io.Writer, arg string, f flags, defaults defaultsFunc) error {
	if f.noColor || os.Getenv("NO_COLOR") != "" {
		lipgloss.SetColorProfile(termenv.Ascii)
	}
	t, err := checks.ParseTarget(arg, f.port)
	if err != nil {
		return err
	}
	o := defaults(f.timeout, f.resolvers)
	o.NoAuth = o.NoAuth || f.noAuth
	res := checks.Run(ctx, t, o, time.Now())

	seed := f.seed
	if seed == "" {
		seed = t.Host
	}
	c := detective.Investigate(res, phrases.Hash(seed))
	ro := render.Options{Version: version, NoTiming: f.noTiming}

	var out string
	switch {
	case f.json:
		if out, err = render.JSON(c, ro); err != nil {
			return err
		}
	case f.serious:
		out = render.Serious(c, ro)
	default:
		out = render.Narrative(c, ro)
	}
	if _, err := io.WriteString(stdout, out); err != nil {
		return err
	}
	if f.serious {
		if c.Failures > 0 {
			return exitError{1}
		}
		return nil
	}
	return exitError{ExitDNS}
}
