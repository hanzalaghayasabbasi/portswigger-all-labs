# DOM-based vulnerabilities Overview

## Lab Levels

Jump directly to the lab writeups:

* [APPRENTICE](./APPRENTICE_Lab.md)
* [PRACTITIONER](./PRACTITIONER_Lab.md)
* [EXPERT](./EXPERT_Lab.md)

  
## Introduction

## What is the DOM?

The **Document Object Model (DOM)** is the browser’s internal representation of a web page. It is a tree-like structure composed of all the HTML elements on the page.

![DOM Representation](https://github.com/sh3bu/Portswigger_labs/assets/67383098/a0e6feed-744b-4c63-89fc-5c55a0110041)

JavaScript can access and manipulate the DOM, changing the page's structure, style, and content dynamically. This powerful feature, when misused or handled insecurely, leads to **DOM-based vulnerabilities**.

These vulnerabilities occur when **attacker-controlled data (source)** is passed into a **dangerous function or object (sink)** without proper validation or sanitization.

---

## Taint-Flow Vulnerabilities

Taint-flow vulnerabilities in the DOM stem from unsafe handling of data that flows from **untrusted sources** to **sensitive sinks**.

---

### What is a Source?

A **source** is any JavaScript property or object that receives data, typically user-controlled. If an attacker can influence the content of a source, and the application fails to handle it safely, it can be abused.

**Common Sources Include:**

* `location.search` – Query string parameters
* `location.hash` – URL fragment identifier
* `document.referrer` – Referring page
* `document.cookie` – User’s cookies
* `window.name` – Window metadata
* `postMessage` – Web messages from other origins

These values can often be manipulated directly by an attacker to inject payloads.

---

### What is a Sink?

A **sink** is a function or property that executes or renders data in a way that can be dangerous if the data is not properly sanitized.

**Examples of Dangerous Sinks:**

* `eval()` – Executes arbitrary JavaScript code
* `document.write()` – Injects HTML into the page
* `element.innerHTML` – Renders raw HTML (possible script injection)
* `element.setAttribute()` – Sets tag attributes, which may be scriptable (e.g., `onerror`, `href`)
* `location.href`, `window.location` – Can cause redirects
* `setTimeout()`/`setInterval()` – Can execute strings as code

---

## DOM Vulnerabilities: Source to Sink

> A DOM-based vulnerability arises when data from a source flows into a sink without validation or sanitization, enabling the attacker to control the sink’s behavior.

Example:

```js
// Vulnerable code
let name = location.search.slice(6);  // source
document.body.innerHTML = "<h1>" + name + "</h1>"; // sink
```

If an attacker accesses the page with `?name=<img src=x onerror=alert(1)>`, the payload gets rendered and executed.

---

## Common DOM-Based Vulnerabilities and Sinks

The table below summarizes typical DOM vulnerabilities and the associated dangerous sinks:

![Common DOM Sinks](https://github.com/sh3bu/Portswigger_labs/assets/67383098/4894c83e-8e67-4d33-be53-d3fef8f28c9a)

---
