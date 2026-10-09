# Contributing

If you find a bug or want to add a provider, please create an issue or submit a pull request. Thanks.

## Fingerprints and live checks

Providers' pages, DNS hosts' behaviour and registries' replies change over time. `live_test.go` checks them against the real services; it only builds with the `live` tag, so ordinary `go test` never touches the network:

```bash
go test -tags live -run TestLive -v .
```

The `live checks` workflow runs it every Monday, on demand, and on pull requests that change `providers.go`, `dns.go`, `http.go`, `nstakeover.go`, `registration.go`, `whois.go` or the test itself. A scheduled or manual run that fails opens an issue, or comments on one already open. A provider that refuses requests from GitHub's runners is skipped, with the reason in the run's summary.

To add a fingerprint:

1. Add a `vPattern` to `providers.go`, with what was matched and when it was verified. Require a CNAME to the provider (`cnames`) where the page alone is too generic to trust, and set `edgeCase` where takeover depends on the provider's conditions.
2. If it can be confirmed live, add the provider to `liveFingerprints` in `live_test.go`, with either an `endpoint` that serves the provider's page for hosts it does not know, or a domain whose unclaimed subdomains (`subdomainOf`) show the same page.
3. Add it to [providers](providers.md), with ✓ if it is in the live checks.

## Tests

```bash
go test -race ./...
```

`scan_test.go` runs whole scans against a fake DNS server, local web servers and a fake registry, so changes to how findings are made, reported or written out are covered end to end.
