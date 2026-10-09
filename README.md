# subtocheck: Subdomain Takeover Checker
[![test](https://github.com/jonhadfield/subtocheck/actions/workflows/test.yml/badge.svg)](https://github.com/jonhadfield/subtocheck/actions/workflows/test.yml)

subtocheck checks a list of domain names for ones that someone else could take over, and reports:

- **dangling CNAMEs**: records pointing at a provider's resource that no longer exists, or at a domain that is unregistered or expiring;
- **dangling DNS delegations**: names delegated to DNS hosts that no longer serve their zone, entirely or in part, or to nameservers on an unregistered domain;
- **unclaimed services**: names whose provider answers with its "no such site" page, matched against fingerprints for over 40 providers, most confirmed against the live provider every week.

It only detects; it never attempts to claim anything.

## What is a subdomain takeover?

If you host a service with a provider such as AWS S3 or Heroku, point a DNS record at it, then delete the service but leave the DNS record, someone else may be able to create a service with the provider that answers for your domain. Many providers do not ask you to prove you own a domain before serving content for it, so if you move out, someone else can move in. It is up to the domain's owner to make sure DNS only points at a provider while the service is live.

## Install

On macOS and Linux, using [Homebrew](https://brew.sh):

```bash
brew install jonhadfield/tap/subtocheck
```

On macOS you can also use the signed, notarized installer, which puts `subtocheck` in `/usr/local/bin`:

```bash
curl -fsSL https://github.com/jonhadfield/subtocheck/releases/latest/download/subtocheck_macos.pkg -o /tmp/subtocheck.pkg && sudo installer -pkg /tmp/subtocheck.pkg -target /
```

On Linux, install the latest release for your architecture:

```bash
curl -fsSL "https://github.com/jonhadfield/subtocheck/releases/latest/download/subtocheck_linux_$(uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/').tar.gz" | sudo tar -xz -C /usr/local/bin subtocheck
```

Otherwise, download the latest release for your platform from the [releases page](https://github.com/jonhadfield/subtocheck/releases) and install it with `install <subtocheck binary> /usr/local/bin/subtocheck` (`sudo install` on Linux). On macOS, a binary downloaded through a browser is quarantined and Gatekeeper will refuse to run it; Homebrew and the installer handle this, but for a downloaded tarball, clear the flag with `xattr -d com.apple.quarantine /usr/local/bin/subtocheck`.

## Quick start

List the names to check, one per line, in `domains.txt`:

```
login.example.com
shop.example.com
static.example.com
```

Then run:

```bash
subtocheck
```

On a terminal, a progress bar shows while it scans, and each potential takeover is printed as soon as it is found:

- `TAKEOVER` (red): the DNS or response matches a provider that lets anyone claim the name;
- `VERIFY` (yellow): an edge case, where takeover depends on the provider's conditions, so check it manually.

A summary follows, and the details of every issue are written to a log file.

## Options

| Option | |
|---|---|
| `--domains <path>` | domain list file (default `domains.txt`) |
| `--log <path>` | log file path (default `subtocheck-<timestamp>.log`) |
| `--json` | write the result to stdout as JSON instead of console output |
| `--config <path>` | email a report after each scan |
| `--quiet` | no console output; the log file is still written |
| `--debug` | also write debug messages to the log file |
| `--workers <n>` | domains checked at once (default 10); more are faster, but busy hosts time out more often, and a timed-out request is a check not made |

## Exit status

| Status | Meaning |
|---|---|
| `0` | no potential takeovers found |
| `1` | an error, such as a missing domains file or a failure to send the email report |
| `2` | at least one potential takeover found, including those to verify manually |

## Documentation

- [How it works](docs/how-it-works.md): each check, and what makes a finding a takeover or one to verify
- [Providers](docs/providers.md): the providers, DNS hosts and fingerprints checked, and those confirmed live every week
- [Output](docs/output.md): the console, the log file, JSON, and email reports with their configuration
- [Contributing](docs/contributing.md): adding fingerprints, the live checks, and tests
