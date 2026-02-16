# Web Cache Poisoning Overview
## Lab Levels

Jump directly to the lab writeups:

* [PRACTITIONER](./PRACTITIONER_Lab.md)
* [EXPERT](./EXPERT_Lab.md)

  
## Introduction

## What is Web Cache Poisoning?

Web cache poisoning is an advanced attack technique that allows an attacker to exploit caching behavior so that a harmful HTTP response is served to other users. The attack unfolds in two primary phases:

1. **Elicit a harmful response** from the origin server using manipulated input.
2. **Get that response cached** so that it's served to other users with equivalent cache keys.

This technique can lead to serious exploits such as:

* Cross-site scripting (XSS)
* Open redirects
* Injection of malicious JavaScript

---

## Understanding Web Cache Behavior

### Types of Caches:

* **Browser Cache** (Local)
* **DNS Cache** (DNS Level)
* **Application Cache** (Server-side)

Web cache poisoning targets **application-level caches**, not browser or DNS caches.

### How Does a Web Cache Work?

A web cache stores server responses to reduce the load and latency of web applications. When a request is made:

* If it's a **cache hit**, the response is served from the cache.
* If it's a **cache miss**, the origin server responds and the cache may store it for future requests.

### Cache Keys

Cache keys determine which responses get reused. They usually include:

* URL path
* Host header
* Optional: query parameters, content type, etc.

**Unkeyed inputs** are request components not included in the cache key. These become the attacker’s point of exploitation.

---

## Impact of Cache Poisoning

The severity depends on:

1. **What payload is cached**: The more dangerous the payload (e.g. XSS), the higher the impact.
2. **Popularity of the page**: A poisoned cache on a high-traffic page amplifies reach.

Even short-lived caches can be re-poisoned continuously, making the effect persistent.

---

Here is your section rewritten in a **clean, consistent, professional format** with centered images and captions to match the rest of your documentation style.

---

## How to Construct a Web Cache Poisoning Attack

### 1. Identify Unkeyed Inputs

Unkeyed inputs are request components that influence the response but are **not included in the cache key**.

These are often headers such as:

* `X-Forwarded-Host`
* `X-Forwarded-For`
* `User-Agent`

Use tools like **Burp Suite – Param Miner**:

* Right-click a request → **Guess headers**
* Review the **Output** tab for interesting behavior or reflected values

> ⚠️ **Caution:** Always use cache busters during testing to avoid poisoning legitimate user traffic.

<p align="center">
  <img src="https://github.com/user-attachments/assets/fe9947bf-c4dc-477e-82d4-e00d8eeb1969" width="800" alt="Param Miner Guess Headers">
  <br>
  <em>Figure: Using Param Miner to identify unkeyed headers</em>
</p>

---

### 2. Elicit a Harmful Response

Once an unkeyed input is discovered:

* Inject payloads and observe response behavior
* Look for reflection in HTML
* Identify dynamic generation based on headers
* Check for insufficient sanitization

The goal is to craft a response that becomes malicious **once cached**.

---

### 3. Get the Response Cached

Ensure the malicious response is cacheable by triggering conditions such as:

* `Cache-Control: public`
* Targeting static-like routes (e.g., `/index.html`)
* Influencing status codes or content types
* Removing `Set-Cookie` headers if necessary

<p align="center">
  <img src="https://github.com/user-attachments/assets/204efe52-05af-4e19-96b3-dee5a6c244b5" width="900" alt="Cached Response Example">
  <br>
  <em>Figure: Example of a cacheable poisoned response</em>
</p>

---

## Exploiting Web Cache Poisoning

### Exploiting Cache Design Flaws

#### Reflected XSS via Unkeyed Headers

```http
GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: a."><script>alert(1)</script>
````

Response:

```html
<meta property="og:image" content="https://a."><script>alert(1)</script>/cms/social.png" />
```

If this response is cached, the malicious payload is served to all subsequent users.

---

### Exploiting Unsafe Resource Imports

```http
GET / HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: evil-user.net
```

Response:

```html
<script src="https://evil-user.net/static/analytics.js"></script>
```

This causes arbitrary JavaScript execution in the browsers of all users who receive the cached page.

---

<p align="center">
  <img src="https://github.com/user-attachments/assets/e63fec68-844f-442b-9f02-4821cc209b08" width="650" alt="Cache Poisoning Impact Diagram">
  <br>
  <em>Figure: Poisoned cache serving malicious content to multiple users</em>
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/7335dccd-a3a5-4f37-bb5a-aa8e8331ab4c" width="850" alt="Web Cache Poisoning Flow">
  <br>
  <em>Figure: End-to-end web cache poisoning attack flow</em>
</p>


---




## Tools

* **Burp Suite Param Miner**: Finds unkeyed inputs automatically
* **Burp Comparer**: Manually compare responses

---

## Additional Resources

* [Practical Web Cache Poisoning (PortSwigger)](https://portswigger.net/web-security/web-cache-poisoning)
* [Gotta Cache 'em all - Whitepaper (Black Hat USA 2024)](https://portswigger.net/research)

---

## Summary

Web cache poisoning is a powerful vulnerability with a wide range of potential impacts. By understanding caching behavior, identifying unkeyed inputs, and crafting harmful yet cacheable responses, attackers can hijack legitimate traffic and distribute malicious content at scale.

**Always test responsibly with cache busters.**
