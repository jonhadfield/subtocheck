package subtocheck

import "regexp"

// Provider fingerprints for detecting subdomains that may be vulnerable to takeover.
//
// Sources, both checked September 2026:
//   - https://github.com/EdOverflow/can-i-take-over-xyz (fingerprints.json): which services are
//     claimable. Only services it rates "Vulnerable" are included, plus a few popular ones it
//     rates "Edge case", which are marked as such and reported as needing manual verification.
//   - https://github.com/projectdiscovery/nuclei-templates (http/takeovers): where a template
//     exists its matchers are used, as they are stricter than the single phrases above.
//   - https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover: the
//     Azure services whose names can be re-registered once a resource is deleted.

// vPattern is an HTTP response fingerprint for a provider that no longer has a service
// configured for the requested host. Every populated field must match.
type vPattern struct {
	platform string
	// edgeCase is set where takeover is only possible under some conditions
	edgeCase bool
	// cnames, if set, requires a CNAME for the host to end in one of these suffixes. It is
	// used where the body fingerprint alone is too generic to trust.
	cnames []string
	// responseCodes, if set, requires the final response status to be one of these
	responseCodes []int
	// bodyStrings are matched according to bodyStringMatch: "all" or "any"
	bodyStrings     []string
	bodyStringMatch string
	// notBodyStrings excludes a match if any of these appear in the body
	notBodyStrings []string
	// headerStrings must all appear, case-insensitively, in the response headers
	headerStrings []string
	// notHeaderStrings excludes a match if any appear, case-insensitively, in the headers
	notHeaderStrings []string
	// redirectStrings requires any redirect followed to have a location containing one of these
	redirectStrings []string
}

var vPatterns = []vPattern{
	{
		platform:        "Agile CRM",
		cnames:          []string{"agilecrm.com"},
		bodyStrings:     []string{"Sorry, this page is no longer available."},
		bodyStringMatch: "all",
	},
	{
		platform:        "Airee.ru",
		bodyStrings:     []string{"Ошибка 402. Сервис Айри.рф не оплачен"},
		bodyStringMatch: "all",
	},
	{
		platform:        "Anima",
		bodyStrings:     []string{"If this is your website and you've just created it, try refreshing in a minute"},
		bodyStringMatch: "all",
	},
	{
		platform: "Azure Front Door",
		// <h2>Our services aren't available right now</h2><p>We're working to restore all services as soon as possible. Please check back soon.</p>
		responseCodes:   []int{400},
		bodyStrings:     []string{"Our services aren't available right now"},
		bodyStringMatch: "all",
	},
	{
		platform:        "Bitbucket",
		bodyStrings:     []string{"Repository not found"},
		bodyStringMatch: "all",
		headerStrings:   []string{"text/plain"},
	},
	{
		platform:        "Campaign Monitor",
		bodyStrings:     []string{"Email Newsletter Software", "css.createsend1.com"},
		bodyStringMatch: "all",
	},
	{
		platform:        "Canny",
		bodyStrings:     []string{"Company Not Found", "There is no such company. Did you enter the right URL?"},
		bodyStringMatch: "all",
	},
	{
		platform:        "Cargo Collective",
		bodyStrings:     []string{`<div class="notfound">`, "404 Not Found<br>"},
		bodyStringMatch: "all",
	},
	{
		platform:        "Gemfury",
		redirectStrings: []string{"gemfury.com/404"},
	},
	{
		// verified live September 2026: unknown hosts redirect to /lpc_not_found.html
		platform:        "GetResponse",
		redirectStrings: []string{"/lpc_not_found.html"},
	},
	{
		platform:        "GetResponse",
		bodyStrings:     []string{"With GetResponse Landing Pages, lead generation has never been easier"},
		bodyStringMatch: "all",
	},
	{
		// verified live September 2026
		platform:        "Ghost",
		bodyStrings:     []string{"Failed to resolve DNS path for this host"},
		bodyStringMatch: "all",
	},
	{
		platform:        "Ghost",
		redirectStrings: []string{"error.ghost.org", "offline.ghost.org"},
	},
	{
		platform: "GitHub Pages",
		edgeCase: true,
		bodyStrings: []string{
			"There isn't a GitHub Pages site here.",
			"For root URLs (like http://example.com/) you must provide an index.html file",
			"For root URLs (like <code>http://example.com/</code>)",
		},
		bodyStringMatch: "any",
	},
	{
		platform:        "HatenaBlog",
		bodyStrings:     []string{"404 Blog is not found"},
		bodyStringMatch: "all",
	},
	{
		platform:        "Help Juice",
		cnames:          []string{"helpjuice.com"},
		bodyStrings:     []string{"We could not find what you're looking for."},
		bodyStringMatch: "all",
	},
	{
		platform:        "Help Scout",
		bodyStrings:     []string{"No settings were found for this company:"},
		bodyStringMatch: "all",
	},
	{
		platform:        "Helprace",
		bodyStrings:     []string{"Alias not configured!", "Admin of this Helprace account needs to set up domain alias"},
		bodyStringMatch: "any",
	},
	{
		platform:        "Heroku",
		edgeCase:        true,
		responseCodes:   []int{404},
		bodyStrings:     []string{"//www.herokucdn.com/error-pages/no-such-app.html", "No such app"},
		bodyStringMatch: "any",
	},
	{
		platform:        "JetBrains YouTrack",
		bodyStrings:     []string{"is not a registered InCloud YouTrack."},
		bodyStringMatch: "all",
	},
	{
		platform:        "LaunchRock",
		cnames:          []string{"launchrock.com"},
		bodyStrings:     []string{"It looks like you may have taken a wrong turn somewhere. Don't worry...it happens to all of us."},
		bodyStringMatch: "all",
	},
	{
		platform:        "Ngrok",
		bodyStrings:     []string{"ngrok.io not found"},
		bodyStringMatch: "all",
	},
	{
		platform:        "Pantheon",
		bodyStrings:     []string{"The gods are wise, but do not know of the site which you seek."},
		bodyStringMatch: "all",
	},
	{
		platform: "Pingdom",
		bodyStrings: []string{
			"Sorry, couldn&rsquo;t find the status page", // verified live September 2026
			"Public Report Not Activated",
			"This public report page has not been activated by the user",
		},
		bodyStringMatch: "any",
	},
	{
		platform:        "Readme.io",
		bodyStrings:     []string{"Project doesnt exist... yet!"},
		bodyStringMatch: "all",
	},
	{
		platform:        "Read the Docs",
		bodyStrings:     []string{"unknown to Read the Docs"},
		bodyStringMatch: "all",
	},
	{
		platform:        "S3",
		responseCodes:   []int{404},
		bodyStrings:     []string{"The specified bucket does not exist", "BucketName"},
		bodyStringMatch: "all",
		// Google Cloud Storage and Alibaba OSS return similar errors but verify domain ownership
		notHeaderStrings: []string{"x-guploader-uploadid", "aliyunoss"},
	},
	{
		platform: "Short.io",
		// verified live September 2026
		bodyStrings:     []string{"Domain not found", "This domain is not configured for link redirection"},
		bodyStringMatch: "all",
	},
	{
		platform:        "SmartJobBoard",
		bodyStrings:     []string{"This job board website is either expired or its domain name is invalid.", "Job Board Is Unavailable"},
		bodyStringMatch: "any",
	},
	{
		platform:        "SmugMug",
		bodyStrings:     []string{`{"text":"Page Not Found"`},
		bodyStringMatch: "all",
	},
	{
		platform:        "Strikingly",
		bodyStrings:     []string{"But if you're looking to build your own website", "you've come to the right place."},
		bodyStringMatch: "all",
	},
	{
		platform:        "Surge.sh",
		cnames:          []string{"surge.sh"},
		responseCodes:   []int{404},
		bodyStrings:     []string{"project not found"},
		bodyStringMatch: "all",
	},
	{
		platform:        "SurveySparrow",
		bodyStrings:     []string{"Account not found.", "ouch!", "SurveySparrow"},
		bodyStringMatch: "all",
	},
	{
		platform:        "Tilda",
		edgeCase:        true,
		bodyStrings:     []string{"Please go to the site settings and put the domain name in the Domain tab."},
		bodyStringMatch: "all",
		notBodyStrings:  []string{"<title>Please renew your subscription</title>"},
	},
	{
		platform:        "Tumblr",
		edgeCase:        true,
		responseCodes:   []int{404},
		bodyStrings:     []string{"Not found.", "assets.tumblr.com", "Whatever you were looking for doesn't currently exist at this address"},
		bodyStringMatch: "all",
	},
	{
		platform: "Uberflip",
		// verified live September 2026
		bodyStrings:     []string{"Non-hub domain", "The URL you've accessed does not provide a hub."},
		bodyStringMatch: "all",
	},
	{
		platform:        "UptimeRobot",
		cnames:          []string{"stats.uptimerobot.com"},
		responseCodes:   []int{404},
		bodyStrings:     []string{"page not found"},
		bodyStringMatch: "all",
		headerStrings:   []string{"server: caddy"},
	},
	{
		platform:        "Wix",
		edgeCase:        true,
		responseCodes:   []int{404},
		bodyStrings:     []string{"ConnectYourDomain Error | Wix.com"},
		bodyStringMatch: "all",
	},
	{
		platform:        "WordPress.com",
		bodyStrings:     []string{"Do you want to register", ".wordpress.com</em> doesn&#8217;t&nbsp;exist"},
		bodyStringMatch: "all",
		notBodyStrings:  []string{"cannot be registered"},
	},
	{
		platform:        "Worksites",
		responseCodes:   []int{404},
		bodyStrings:     []string{"Company Not Found", "worksites.net"},
		bodyStringMatch: "all",
	},
}

// cnamePattern identifies a provider from the target of a CNAME that no longer resolves.
// For these providers a deleted resource's name can be registered again by anyone, so a
// dangling CNAME to one of them is itself the vulnerability; there is no page to fingerprint.
type cnamePattern struct {
	platform string
	suffixes []string
}

var cnamePatterns = []cnamePattern{
	{
		platform: "AWS Elastic Beanstalk",
		suffixes: []string{"elasticbeanstalk.com"},
	},
	{
		platform: "Azure",
		suffixes: []string{
			"azurewebsites.net",     // App Service, including slots
			"cloudapp.net",          // classic cloud services
			"cloudapp.azure.com",    // public IP addresses
			"trafficmanager.net",    // Traffic Manager
			"blob.core.windows.net", // Blob Storage
			"azureedge.net",         // CDN
			"azurefd.net",           // Front Door
			"azurecontainer.io",     // Container Instances
			"azure-api.net",         // API Management
			"chinacloudapp.cn",      // classic cloud services, sovereign clouds
			"usgovcloudapp.net",
			"azurecloudapp.de",
		},
	},
	{
		platform: "Discourse",
		suffixes: []string{"trydiscourse.com"},
	},
}

// nsPattern identifies a DNS hosting provider from the hostnames of the nameservers a
// name is delegated to. If none of those nameservers serves the zone, it has been deleted
// from the provider, and where the provider lets any account create a zone of that name,
// whoever does so controls every record under it.
//
// Source, checked October 2026: https://github.com/indianajson/can-i-take-over-dns.
// Providers it rates "Not Vulnerable", such as Route 53 and Cloudflare, are not listed:
// a dangling delegation to them is reported as a DNS issue instead.
type nsPattern struct {
	platform string
	edgeCase bool
	// note is shown with a finding, for conditions on the takeover
	note        string
	nameservers *regexp.Regexp
}

var nsPatterns = []nsPattern{
	{platform: "DigitalOcean DNS", nameservers: regexp.MustCompile(`^ns[1-3]\.digitalocean\.com$`)},
	{platform: "DNS Made Easy", nameservers: regexp.MustCompile(`^ns\d+\.dnsmadeeasy\.com$`)},
	{platform: "Domain.com DNS", note: "requires a paid account", nameservers: regexp.MustCompile(`^ns[12]\.domain\.com$`)},
	{platform: "Hurricane Electric DNS", nameservers: regexp.MustCompile(`^ns[1-5]\.he\.net$`)},
	{platform: "Linode DNS", nameservers: regexp.MustCompile(`^ns\d+\.linode\.com$`)},
	{platform: "Name.com DNS", note: "requires a paid account", nameservers: regexp.MustCompile(`^ns[1-4][a-z0-9]*\.name\.com$`)},
	{platform: "Reg.ru DNS", nameservers: regexp.MustCompile(`^ns\d\.reg\.ru$`)},
	{platform: "TierraNet DNS", nameservers: regexp.MustCompile(`^ns[12]\.domaindiscover\.com$`)},
	{platform: "Yahoo Small Business DNS", note: "requires a paid account", nameservers: regexp.MustCompile(`^yns[12]\.yahoo\.com$`)},
	{platform: "Azure DNS", edgeCase: true, nameservers: regexp.MustCompile(`^ns[1-4]-\d+\.azure-dns\.(com|net|org|info)$`)},
	{platform: "DreamHost DNS", edgeCase: true, nameservers: regexp.MustCompile(`^ns[1-3]\.dreamhost\.com$`)},
	{platform: "Google Cloud DNS", edgeCase: true, nameservers: regexp.MustCompile(`^ns-cloud-[a-z]\d+\.googledomains\.com$`)},
}

// nsProvider returns the pattern matching all of a delegation's nameservers, if any.
func nsProvider(nameservers []string) (nsPattern, bool) {
	for _, p := range nsPatterns {
		matched := len(nameservers) > 0
		for _, ns := range nameservers {
			if !p.nameservers.MatchString(ns) {
				matched = false
				break
			}
		}
		if matched {
			return p, true
		}
	}
	return nsPattern{}, false
}
