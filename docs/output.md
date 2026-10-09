# Output

## Console

On a terminal, subtocheck shows a progress bar while it scans and prints each potential takeover in colour as soon as it is found, as `TAKEOVER` (red) or `VERIFY` (yellow), followed by a summary with counts of findings, DNS issues and request errors.

When the output is not a terminal, for example piped or run from cron, the progress bar and colours are left out. Colour can also be turned off with `NO_COLOR=1`.

## Log file

The details of every issue, including each DNS issue and request error, are written to a log file: `subtocheck-<timestamp>.log` in the current directory, or the path given with `--log`. The file is only created if there is something to record. With `--debug`, debug messages are written to it too.

## JSON

With `--json`, the result is written to stdout as a single JSON document instead of the console output, for other tools to consume:

```json
{
  "domains": 3,
  "duration_seconds": 0.5,
  "summary": { "takeovers": 1, "verify": 0, "dns_issues": 1, "request_errors": 0 },
  "findings": [
    {
      "host": "app.example.com",
      "platform": "Framer",
      "kind": "takeover",
      "urls": ["http://app.example.com", "https://app.example.com"]
    }
  ],
  "dns_issues": [{ "target": "old.example.com", "error": "old.example.com could not be resolved (...)" }],
  "request_errors": [],
  "log": "subtocheck-20261007-071203.log"
}
```

A finding's `kind` is `takeover`, or `verify` for edge cases to check manually; it may also have a `detail`, such as a CNAME target or a domain's expiry stage. Each host and platform appears once, takeovers first. Lists are empty rather than absent, and `log` is left out when no log was written. The log is still written, and the exit status is unchanged.

## Email reports

With `--config <path>`, a report is emailed after each scan, through SMTP (TLS only) or AWS SES. It has a plain text and an HTML version. Its subject gives the number of potential takeovers and those to verify, after the configured subject (default "subtocheck scan"). It lists each finding, as `TAKEOVER` or `VERIFY`, with its platform, the detail of what was found and the URLs it was found at, along with counts of DNS issues and request errors. The scan's log is attached.

The configuration is YAML. For SMTP:

```yaml
email:
  provider: smtp
  host: "<SMTP HOST>"
  port: "<SMTP PORT>"
  username: "<USER ID>"
  password: "<PASSWORD>"
  subject: "<EMAIL SUBJECT>"     # optional
  source: "<FROM ADDRESS>"
  recipients:
    - "<EMAIL RECIPIENT 1>"
    - "<EMAIL RECIPIENT 2>"
  skip_no_vulns: false           # optional: true to send nothing when there are no potential takeovers
```

For SES:

```yaml
email:
  provider: ses
  region: "<AWS REGION>"
  subject: "<EMAIL SUBJECT>"     # optional
  source: "<FROM ADDRESS>"
  recipients:
    - "<EMAIL RECIPIENT 1>"
    - "<EMAIL RECIPIENT 2>"
  aws_access_key_id: "<ACCESS KEY ID>"            # optional, see below
  aws_secret_access_key: "<SECRET ACCESS KEY>"    # optional, see below
  aws_session_token: "<SESSION TOKEN>"            # optional, with temporary credentials
```

With SES, the suggested approach is to run subtocheck on an EC2 instance with an instance profile (IAM role) that has only the permissions needed to send email, so no credentials are written down and those used are temporary. Elsewhere, if `aws_access_key_id` and `aws_secret_access_key` are not given, subtocheck uses the standard AWS credential sources, such as environment variables and shared configuration.

No email is sent when a scan finds nothing at all. A report that cannot be sent exits with status 1.
