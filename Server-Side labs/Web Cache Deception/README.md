# Web Cache Deception – Vulnerability Guide

## Overview

**Web Cache Deception** is a vulnerability that allows attackers to trick a web cache into storing sensitive, user-specific content. This happens due to discrepancies between how the **cache server** and **origin server** interpret requests.

An attacker lures a victim into accessing a malicious URL. The victim’s request causes their private content to be cached. The attacker can then send the same request and access the cached content.
<img width="962" height="505" alt="image" src="https://github.com/user-attachments/assets/b10edc36-24b9-4cbc-9178-dfa847ebf148" />

---

## Key Difference from Web Cache Poisoning

While both exploit caching:

- **Web Cache Deception**: Tricks cache into storing **private content**, which the attacker can later retrieve.
- **Web Cache Poisoning**: Injects **malicious content** into a cache, affecting what other users see.

> Many of these labs are based on original research presented at **Black Hat USA 2024**.  
> For more information, refer to the whitepaper:  
> **_Gotta Cache 'em all: Bending the rules of web cache exploitation_**

---

## What is a Web Cache?

A **web cache** is a layer between the user and the origin server that stores static resources. When a request is made:

- **Cache miss**: The cache does not have the resource → forwards request to origin server → stores the response.
- **Cache hit**: The requested resource is served directly from the cache (faster, reduces server load).

 <img width="1067" height="278" alt="image" src="https://github.com/user-attachments/assets/0bd11bb8-cbd2-4a67-a1c7-6655e5df4722" />

### Example Use Case: CDNs

**Content Delivery Networks (CDNs)** use caching to:

- Store static resources close to users
- Improve page load speed
- Reduce latency

---

## How Caching Works

### Cache Keys

The cache creates a **cache key** using elements from the HTTP request. This usually includes:

- URL path
- Query parameters
- (Sometimes) Headers or content-type

If two requests generate the same key, the cached version is served.

> To learn more about manipulating cache keys, refer to:  
> [Web Cache Poisoning – PortSwigger Academy](https://portswigger.net/web-security/web-cache-poisoning)

---

## Cache Rules

Cache rules decide **what** to store and for **how long**. They typically:

- **Allow** static resources (e.g. `.css`, `.js`, `robots.txt`)
- **Disallow** dynamic/private content (e.g. `/account`, `/checkout`)

### Common Rule Types

- **Static File Extension Rules**: Match `.js`, `.css`, `.jpg`, etc.
- **Static Directory Rules**: Match `/static/`, `/assets/`, etc.
- **Filename Rules**: Match specific files like `robots.txt`, `favicon.ico`
- **Custom Rules**: Based on headers, parameters, or dynamic logic

---

## Constructing a Web Cache Deception Attack (How to Perform the Attack)


### 1. Identify a Target

Find an endpoint that returns **dynamic** content (e.g. user info, order history).  
Use Burp Suite to inspect responses. Focus on:

- Endpoints supporting `GET`, `HEAD`, `OPTIONS` (not `POST`, `PUT`, etc.)

### 2. Find a Discrepancy in Parsing

Look for differences in how the **cache** and **origin server** handle:

- Path structure
- Delimiters
- Normalization

### 3. Craft a Malicious URL

Create a request that:

- Appears **cacheable** to the cache
- Returns **sensitive content** from the origin

Then:

- Have a victim access the malicious URL
- The response (containing private data) is stored in cache
- You (attacker) access the same URL and retrieve the cached version

> ⚠️ Avoid testing in-browser if redirections or JS might interfere. Use Burp Suite.

---

## Using a Cache Buster

To prevent interference from previously cached responses:

- Append **random query parameters** to each request
- Use **Param Miner**'s dynamic cache buster:

```plaintext
Burp → Param Miner → Settings → Add dynamic cachebuster
````

Each request will now have a unique query string, forcing a cache miss.

---

## Detecting Cached Responses

### Response Headers

* `X-Cache: hit` → Response served from cache
* `X-Cache: miss` → Response fetched from origin
* `X-Cache: dynamic` → Origin-generated content, not cached
* `X-Cache: refresh` → Cached copy was refreshed
* `Cache-Control: public, max-age=3600` → Indicates cacheable content (but not definitive)

* \

### Response Time

* Significant **decrease in response time** often indicates a cache hit

---

## Summary

Web Cache Deception exploits flaws in caching logic to expose private data.
By understanding:

* Cache keys
* Cache rules
* Header behavior

You can identify, craft, and test for these attacks effectively using tools like **Burp Suite**, **Collaborator**, and **Param Miner**.

---

## Appendix: Useful Payload Data

The following lists are useful while testing for cache deception attacks:

### 📁 Default Cacheable File Extensions

These extensions are often treated as static and cached automatically by load balancers and CDNs:

```plaintext
.txt .7z .csv .gif .midi .png .tif .zip
.avi .doc .gz .mkv .ppt .tiff .ico .zst
.xci .mp3 .pptx .ttf .css .apk .dmg .iso
.mp4 .ps .webm .flac .bin .ejs .jar .ogg
.rar .web .pmid .bm .peot .jpg .otf .svg
.woff .pls .bz2 .eps .jpeg .pdf .tar .class
.exe .jsp .pict .swf .xls .xlsx .zwoff2
```

📄 **View full list**:
[https://gist.github.com/hanzalaghayasabbasi/08aca83e1f485d5b5009737c9e26f4d9](https://gist.github.com/hanzalaghayasabbasi/08aca83e1f485d5b5009737c9e26f4d9)

---

### 🔣 Delimiter Characters for Bypasses

These characters and their encoded versions are useful for introducing URL parsing ambiguity:

```plaintext
! " # $ % & ' ( ) * + , - . / : ; < = > ? @ [ \ ] ^ _ ` { | } ~
%21 %22 %23 %24 %25 %26 %27 %28 %29
%2A %2B %2C %2D %2E %2F
%3A %3B %3C %3D %3E %3F
%40 %5B %5C %5D %5E %5F
%60 %7B %7C %7D %7E
```

📄 **View full list**:
[https://gist.github.com/hanzalaghayasabbasi/fb3100dfc62fec0253a0d2f0a8905fc5](https://gist.github.com/hanzalaghayasabbasi/fb3100dfc62fec0253a0d2f0a8905fc5)

---

## Additional Reading

* 🧠 [Gotta Cache 'em all – Whitepaper (Black Hat 2024)](https://www.blackhat.com/us-24/briefings/schedule/index.html#gotta-cache-em-all-bending-the-rules-of-web-cache-exploitation-35336)
* 🧪 [Web Cache Deception Research – PortSwigger](https://portswigger.net/research/web-cache-deception)

