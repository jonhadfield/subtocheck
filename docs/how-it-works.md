# How subtocheck works

For each name in the domain list, subtocheck:

1. resolves it, following any CNAME records, and checks what the DNS says;
2. walks the delegations from the top-level domain down to it, asking each zone's own nameservers;
3. if it resolves, requests its root over http and https and compares each response with the fingerprints of providers that no longer have a service configured for it.

subtocheck only detects; it never attempts to claim anything. Only public DNS, registries' RDAP and WHOIS services, and the names being checked are queried.

Findings are reported as either:

- `TAKEOVER`: the DNS or response matches a provider that lets anyone claim the name;
- `VERIFY`: an edge case, where takeover depends on the provider's conditions, such as its domain verification, so it should be checked manually.

## Dangling CNAMEs

If the name has a CNAME whose target does not exist (NXDOMAIN), the record is dangling.

Where the target belongs to a provider that lets anyone register a deleted resource's name again, such as Azure App Service, that is a potential takeover; no request is needed. See [providers](providers.md#dangling-cnames) for the list.

For other dangling CNAMEs, subtocheck checks whether the target's domain is registered: first in DNS, then with the domain's registry over [RDAP](https://about.rdap.org/), or its WHOIS server for registries without an RDAP service (such as `.io`, `.de` and `.jp`). If the registry has no record of it, anyone could register it and serve content for your name, so it is a potential takeover. Registries also report names they reserve as unregistered, though those cannot be bought, which is why the finding says the domain "may be available to register".

A domain that is registered but has no nameservers is reported to verify manually, with how far through expiry the registry says it is, and its expiry date:

| Registry status | Reported as |
|---|---|
| pending delete | Domain pending deletion: available to register within days |
| redemption period | Domain in redemption: deleted and released unless the registrant restores it |
| client or server hold | Domain on hold: registered but suspended |
| auto renew period, or an expiry date in the past | Expired domain: in its renewal grace period |
| none of these | Undelegated domain |

A domain whose registry cannot confirm either way is also reported to verify manually. Dangling CNAMEs to a domain that is registered, or within your own domain, are reported as DNS issues.

## Delegations and nameservers

subtocheck follows each name's delegations from the top-level domain down, asking each zone's nameservers directly rather than a resolver, as resolvers only report a generic failure for these problems. A nameserver serves a zone only if it answers authoritatively with that zone's own SOA record.

- **Dangling delegation.** A name delegated to nameservers that do not serve its zone, usually because the zone was deleted from the DNS host. Where the host lets any account create a zone of that name, whoever does so controls every record under it, so it is a potential takeover; otherwise it is a DNS issue.
- **Partly dangling delegation.** Some of the nameservers serve the zone and others do not. Resolvers pick nameservers at random, so if those that do not serve it are on a host where anyone can create the zone, whoever does so answers a share of its queries: a potential takeover. Any other partly dangling delegation is a DNS issue.
- **Nameserver on an unregistered domain.** A nameserver whose hostname does not exist and whose domain is not registered. Whoever registers that domain answers a share of the zone's queries, even if its other nameservers are healthy, so it is a potential takeover. Registration is checked as for dangling CNAMEs.

See [providers](providers.md#dns-hosts) for the DNS hosts subtocheck identifies.

## Response fingerprints

If the name resolves, subtocheck requests it over http and https, following redirects, and compares each response with the fingerprints of providers that are not serving anything for it: their "no such site" page, a header, a redirect, or a CNAME to the provider where the page alone is too generic to trust. A host that matches over both http and https is one finding.

Certificates are not verified, as a dangling name is answered by its provider with the provider's own certificate rather than one for the name. Responses are only matched against fingerprints; nothing is sent and nothing in them is trusted.

If the name cannot be resolved, it is not in public DNS, so it cannot be taken over publicly; if it resolves but neither http nor https responds, there is no response to fingerprint. Both are recorded in the log.

See [providers](providers.md#response-fingerprints) for the fingerprints, and which are confirmed against the live provider every week.
