
# subtocheck: Subdomain Takeover Checker
[![CircleCI](https://circleci.com/gh/jonhadfield/ape/tree/master.svg?style=shield&circle-token=16e5cf0096cd4f6c7894e10f25b51e07746fa0b7)](https://circleci.com/gh/jonhadfield/ape/tree/master)

- [about](#about)
- [compatibility](#compatibility)
- [what is a subdomain takeover?](#what-is-a-subdomain-takeover)
- [how does subtocheck work?](#how-does-subtocheck-work)
- [install and run](#install-and-run)
- [sending email reports](#sending-email-reports)
- [contributing](#contributing)

## <a name="about"></a>about

subtocheck is a command line tool that accepts a list of FQDNs (Fully Qualified Domain Names) to see if they're vulnerable to being taken over.

## <a name="compatibility"></a>compatibility

Only tested on Linux and MacOS, but should work on others.

## <a name="what-is-a-subdomain-takeover"></a>what is a subdomain takeover?

If you host a service on certain hosting providers, e.g. AWS CloudFront and Heroku, point a DNS record to the provider and then delete your service from that provider (but leave your DNS pointing at the provider), it is possible for someone else to create a new service on that provider that responds to requests for your domain.
This is possible because a number of providers do not ask you to prove you own the domain before hosting your content. In other words, if you move out, someone else can move in and take advantage of your own domain still pointing to the provider.
The onus is on the customer to ensure their DNS only resolves to the provider whilst that service is live.

## <a name="how-does-subtocheckwork"></a>how does subtocheck work?

subtocheck performs three checks for each FQDN:
- DNS resolution
- A request to the root of the domain over http and https
- Test each response against a provider that no longer has a service configured

If the name cannot be resolved then the FQDN is not in public DNS and therefore it isn't vulnerable to a public subdomain takeover.

If the name can be resolved but responses cannot be retrieved over http nor https then it isn't vulnerable to a public subdomain takeover.

If the response (over http and/or https) can be retrieved, then check the built-in signatures for a provider match. A provider match indicates someone may be able to host a service for your domain.

#### checks are currently configured for providers:

- AWS CloudFront
- Heroku
- AWS S3
- Tumblr

## <a name="install-and-run"></a>install and run

Download the latest release here: https://github.com/jonhadfield/subtocheck/releases and install:

``
$ install <subtocheck binary> /usr/local/bin/subtocheck
``

Add your list of domains to a file called 'domains.txt' (you can override with --domains option)

    login.example.com
    shop.example.com
    static.example.com

Run subtocheck

``
$ subtocheck
``

## <a name="sending-email-reports"></a>sending email reports

SMTP (TLS Only) and AWS SES (Simple Email Service) are supported. If defined, then a report will be emailed that includes a body with a count of respective issues and a list of FQDNs that may be vulnerable to takeovers. Attached to the email will be separate lists of DNS and request issues encountered during the scan.

Email configuration is defined as YAML. For SMTP create a file containing this configuration:

    email:
      provider: smtp
      host: "<SMTP HOST>"
      port: "<SMTP PORT>"
      username: "<USER ID>"
      password: "<PASSWORD>"
      subject: "<EMAIL SUBJECT>"
      source: "<FROM ADDRESS>"
      recipients:
        - "<EMAIL RECIPIENT 1>"
        - "<EMAIL RECIPIENT 2>"
        ...
        
For SES, use the following:

    email:
      provider: ses
      region: "<AWS REGION>"
      subject: "<EMAIL SUBJECT>"
      source: "<FROM ADDRESS>"
      recipients:
        - "<EMAIL RECIPIENT 1>"
        - "<EMAIL RECIPIENT 2>"
        ...
      aws_access_key_id: <ACCESS KEY ID>   // optional (see below)
      aws_secret_access_key: <SECRET ACCESS KEY>    // optional (see below)

 When using the SES provider, the suggested approach is to run subtocheck on an EC2 instance with an Instance Profile (IAM Role) that has the minimum permissions required to send an email. This will prevent hard-coding credentials and ensure the credentials used are temporary only.
 
 If you decide to run outside of AWS then subtocheck will read credentials from the user's environment, e.g. Environment Variables, if 'aws_access_key_id' and 'aws_secret_access_key' are not specified.

 Run subtocheck, specifying email configuration
 
 ``
 $ subtocheck --config <config>.yaml
 ``

## <a name="contributing"></a>contributing

If you find any bugs or want to add another provider pattern, please create and issue or submit a PR. Thanks.
