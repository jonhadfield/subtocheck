# Providers

Providers and fingerprints are based on:

- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz), for which services are claimable;
- the [nuclei takeover templates](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/takeovers), whose matchers are used where they are stricter, and some services only they list, where their pages were confirmed live;
- Microsoft's [dangling DNS guidance](https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover), for Azure;
- [can-i-take-over-dns](https://github.com/indianajson/can-i-take-over-dns), for DNS hosts.

Providers change their pages over time. Fingerprints marked ✓ are confirmed against the live provider every week by the `live checks` workflow, which opens an issue when one stops matching; the rest could not be checked automatically, as the provider blocks such requests or has no page to probe.

## Dangling CNAMEs

A CNAME to a name that does not exist under these is a potential takeover, as anyone can create a resource with that name again:

- AWS Elastic Beanstalk
- Azure: App Service, Cloud Services, Public IP addresses, Traffic Manager, Blob Storage, CDN, Front Door, Container Instances, API Management
- Discourse

A dangling CNAME to any other domain is checked for whether that domain can be registered; see [how it works](how-it-works.md#dangling-cnames).

## DNS hosts

A dangling or partly dangling delegation to these is a potential takeover, as any account can create the deleted zone again:

- DigitalOcean, DNS Made Easy, Hurricane Electric, Linode, Reg.ru, TierraNet
- Domain.com, Name.com and Yahoo Small Business, where takeover requires a paid account
- Edge cases, reported to verify manually: Azure DNS, DreamHost, Google Cloud DNS

A dangling delegation to any other host, such as Route 53 or Cloudflare, is reported as a DNS issue. Each host's identification and refusal of unhosted zones are among the weekly live checks.

## Response fingerprints

| | | |
|---|---|---|
| Agile CRM | Airee.ru ✓ | Anima ✓ |
| Azure Front Door ✓ | Bitbucket ✓ | Campaign Monitor ✓ |
| Canny ✓ | Cargo Collective ✓ | Framer ✓ |
| Gemfury ✓ | GetResponse ✓ | Ghost ✓ |
| GitBook ✓ | HatenaBlog ✓ | Help Juice ✓ |
| Help Scout ✓ | Helprace | JetBrains YouTrack |
| LaunchRock ✓ | Leadpages ✓ | Ngrok ✓ |
| Pantheon ✓ | Pingdom ✓ | Readme.io |
| Read the Docs ✓ | S3 ✓ | Short.io ✓ |
| SmartJobBoard ✓ | SmugMug ✓ | Strikingly |
| Surge.sh ✓ | SurveySparrow | Uberflip ✓ |
| UptimeRobot | UserVoice ✓ | Wasabi ✓ |
| WordPress.com ✓ | Wufoo ✓ |  |

Edge cases, reported to verify manually, as takeover depends on conditions such as the provider's domain verification: GitHub Pages ✓, Heroku ✓, Netlify ✓, Tilda ✓, Tumblr ✓, Vercel ✓, Wix. The current Azure Front Door and Ngrok pages are also reported to verify manually: Front Door validates custom domains, and Ngrok shows the same page when a configured endpoint is simply offline.

## Not checked

- **Shopify** and **Webflow**: neither serves a distinctive page for a custom domain it does not know.
- **Teamwork**, **Big Cartel** and **Better Stack**: listed by nuclei, but their pages for unclaimed names could not be confirmed.
- Services rated not vulnerable by can-i-take-over-xyz, such as CloudFront, Fastly, Google Cloud Storage, HubSpot, Kinsta and Zendesk.
