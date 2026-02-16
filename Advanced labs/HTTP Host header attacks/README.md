# HTTP Host Header and Host Header Attacks


## Lab Levels

Jump directly to the lab writeups:

* [APPRENTICE](./APPRENTICE_Lab.md)
* [PRACTITIONER](./PRACTITIONER_Lab.md)
* [EXPERT](./EXPERT_Lab.md)

  
Your section is already clear and well-structured. To make it **more visually consistent with your other sections** (like SSRF or Web Cache), you can **center the image with a caption**. Here's a polished version:


## Introduction

## What is the HTTP Host Header?

The HTTP `Host` header is a mandatory component of HTTP/1.1 requests. It specifies the domain name the client wants to access:

```http
GET /web-security HTTP/1.1
Host: portswigger.net
````

<p align="center">
  <img src="https://github.com/user-attachments/assets/7d5f8893-4ca1-455d-a755-3343de9fa59c" width="700" alt="HTTP Host Header Diagram">
  <br>
  <em>Figure: Example of an HTTP request showing the Host header</em>
</p>

### Purpose of the Host Header

* **Virtual Hosting**: Helps servers distinguish between multiple websites hosted on the same IP.
* **Routing via Intermediaries**: Guides reverse proxies/load balancers/CDNs to the correct back-end.

### Analogy

Think of the `Host` header like an apartment number in a shared building — it directs the mail (HTTP request) to the correct recipient (website/application).

---


## HTTP Host Header Attacks

### Definition

Host header attacks occur when a server mishandles or implicitly trusts the user-controlled `Host` header, leading to security vulnerabilities.

### Vulnerabilities Include:

* **Web Cache Poisoning**
* **Business Logic Flaws**
* **Routing-based SSRF**
* **Classic Server-Side Issues (e.g., SQLi)**

---

## Why Do Host Header Vulnerabilities Arise?

1. **Implicit Trust**: Assuming the `Host` header is not user-controlled.
2. **Poor Validation**: Not validating or escaping the header properly.
3. **Insecure Defaults**: Many third-party tools trust headers like `X-Forwarded-Host` by default.
4. **Discrepancies Between Components**: Front-end and back-end systems might interpret headers differently.

---

## How to Test for HTTP Host Header Vulnerabilities

### 1. Supply Arbitrary Host

```http
Host: attacker.com
```

Check for reflection, redirects, absolute URLs in response.

### 2. Use Invalid Ports or Subdomains

```http
Host: vulnerable.com:evil
Host: notvulnerable-website.com
Host: hacked-subdomain.vulnerable.com
```

### 3. Inject Duplicate Host Headers

```http
Host: vulnerable.com
Host: attacker.com
```

### 4. Use Absolute URLs

```http
GET https://vulnerable.com/ HTTP/1.1
Host: attacker.com
```

### 5. Line Wrapping Trick

```http
Host: attacker.com
 Host: vulnerable.com
```

---

## Host Header Override Headers

If `Host` is validated but other headers aren't:

```http
Host: vulnerable.com
X-Forwarded-Host: attacker.com
```

Other headers to try:

* `X-Host`
* `X-Forwarded-Server`
* `X-HTTP-Host-Override`
* `Forwarded`

---

## Mitigation Techniques

1. **Strict Validation**: Enforce a whitelist of valid hostnames.
2. **Canonicalization**: Normalize and verify host before using it.
3. **Avoid User-Controlled URLs**: Do not generate absolute URLs from headers.
4. **Disable Unused Headers**: Remove support for `X-Forwarded-Host`, etc., unless explicitly required.
5. **Application-Level Checks**: Validate any usage of the `Host` header within the app logic.

---

## Tools for Testing

* **Burp Suite (Proxy, Repeater, Intruder)**
* **curl, Postman** (for manual header tampering)

---
