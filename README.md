# its-always-dns

A network troubleshooter that runs real checks, narrates them as a detective case, and always concludes that it was DNS.

The evidence section tells you what actually broke. The exit code is always 53.

```
$ its-always-dns https://expired.badssl.com
  CASE #1884: The Forgotten Hosts File
  Target expired.badssl.com:443   Investigator its-always-dns 1.0.0

  Suspect 1: The Resolver
    resolv.conf           nameserver 8.8.8.8, search svc.cluster.local cluster.local, ndots:5
    ndots                 ndots:5 with 2 search domains: expired.badssl.com tries 2 wrong names before the real one. Add a trailing dot or lower ndots
    system lookup         expired.badssl.com -> 104.154.89.105  96 ms
    system 8.8.8.8        104.154.89.105 (TTL 23)  21 ms
    1.1.1.1               104.154.89.105 (TTL 282)  4 ms
    authoritative         104.154.89.105 (TTL 300) from ns-cloud-c1.googledomains.com  162 ms
    Verdict: Suspicious.

  Suspect 2: The Network
    connect               104.154.89.105:443 connected  282 ms
    Verdict: Cleared.

  Suspect 3: The Certificate
    handshake             certificate expired 4188 days ago (2015-04-12)  705 ms
    Verdict: Guilty.

  Suspect 4: The Application
    skipped               not questioned: the TLS handshake failed first
    Verdict: Not questioned.

  ────────────────────────────────────────────
  It was DNS.

  The DNS would like you to know it has an alibi. The Certificate did it: certificate expired 4188 days ago (2015-04-12).

  Exit code 53. Use --serious for a boring report.
```

That run was inside a container with Kubernetes-style DNS settings, which is why the ndots warning shows up. It is real, and it costs every pod a few wasted lookups per request.

## Install

```sh
brew install khimananda/tap/its-always-dns
```

```sh
go install github.com/khimananda/its-always-dns/cmd/its-always-dns@latest
```

```sh
docker run --rm ghcr.io/khimananda/its-always-dns example.com
```

Or grab a binary from the [releases page](https://github.com/khimananda/its-always-dns/releases).

### Inside a Kubernetes cluster

Where DNS actually breaks. This runs with the pod's own resolv.conf, so the cluster DNS, search domains and ndots are the real ones:

```sh
kubectl run dns-check --rm -it --restart=Never \
  --image=ghcr.io/khimananda/its-always-dns -- my-service.my-namespace
```

## Usage

```sh
its-always-dns api.example.com                  # https on 443 by default
its-always-dns https://example.com/health       # a specific URL
its-always-dns db.internal:5432                 # plain TCP, no TLS or HTTP
its-always-dns example.com --resolver 9.9.9.9   # question another resolver too
its-always-dns example.com --serious            # boring report, exit 0 or 1
its-always-dns example.com --json | jq .actual_culprit
its-always-dns why                              # learn one real way DNS breaks
its-always-dns haiku
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--serious` | off | Plain report. Exit 0 when nothing failed, 1 otherwise. Use this in scripts |
| `--json` | off | The whole case as JSON. Combine with `--serious` for script-friendly exit codes |
| `-p, --port` | from URL, else 443 | Port to test |
| `--timeout` | `3s` | Timeout for each check |
| `--resolver` | none | Extra resolver to question, repeatable |
| `--no-authoritative` | off | Skip the authoritative name server lookup |
| `--no-timing` | off | Hide durations, for reproducible output |
| `--seed` | the host | Changes the case number and title |
| `--no-color` | off | No colors. `NO_COLOR` is honoured too |

## What it checks

| Suspect | Checks |
|---------|--------|
| The Resolver | Parses `/etc/resolv.conf` and warns about the ndots trap. Times the system lookup, the one your app does. Queries the system nameserver, 1.1.1.1 and 8.8.8.8 directly and compares their answers. Finds the zone's authoritative name server and asks it without recursion |
| The Network | TCP connect to the address the system lookup returned |
| The Certificate | TLS handshake. Reports expiry, wrong hostname and untrusted issuers in plain words |
| The Application | One HTTP GET to the same address. Reports status, redirects and the `Server` header |

Each suspect is cleared, suspicious, guilty or not questioned. Later suspects are skipped when an earlier one makes them impossible to question: no address means no TCP, and a failed handshake means no HTTP.

DNS is never simply cleared. At best it is "Cleared. Allegedly." When something else broke, DNS gets an alibi that names the real culprit.

A public resolver that does not answer is reported as information, not failure. Many corporate networks block outbound DNS, and that is itself useful to know.

On macOS, apps resolve through the system configuration rather than `/etc/resolv.conf` alone, so the resolv.conf line is a hint there. On Linux and in containers it is the real thing.

## Add a line

Case titles live in [internal/phrases/titles.txt](internal/phrases/titles.txt). Real DNS failure modes for `why` live in [internal/phrases/why.txt](internal/phrases/why.txt). See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
