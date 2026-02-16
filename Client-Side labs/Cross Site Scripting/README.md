# Cross-Site Scripting (XSS) Overview


## Lab Levels

Jump directly to the lab writeups:

* [APPRENTICE](./APPRENTICE_Lab.md)
* [PRACTITIONER](./PRACTITIONER_Lab.md)
* [EXPERT](./EXPERT_Lab.md)

  
## Introduction


**Cross-site scripting (XSS)** is a security vulnerability that allows an attacker to inject malicious scripts into web pages viewed by other users. These scripts are usually executed in the context of the victim’s browser, allowing attackers to steal cookies, perform actions on behalf of the victim, or redirect them to malicious sites.

There are **three main types of XSS**:

1. Reflected XSS (Non-Persistent)
2. Stored XSS (Persistent)
3. DOM-Based XSS

---

## 1. Reflected Cross-Site Scripting (Non-Persistent)

**Reflected XSS** occurs when a malicious script is **reflected off a web server**, such as in an error message, search result, or any other response that includes input sent in the request.

The malicious payload is delivered via a URL, and it **does not get stored** anywhere. The attack only works if the user **clicks the link** crafted by the attacker.

### Example Scenario

**`login.php`**

```html
<form action="welcome.php" method="GET">
  <input name="name" type="text">
  <input type="submit" value="Login">
</form>
```

**`welcome.php`**

```php
<?php
  echo "Welcome, " . $_GET['name'];
?>
```

### Attack Payload

The attacker sends a link:

```
https://vulnerable-site.com/welcome.php?name=<script>alert(1)</script>
```

If a victim clicks the link, the browser executes the script.

### Fix

Escape and sanitize user input before displaying it:

```php
echo "Welcome, " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
```

### Automated Detection

Tools like **Burp Suite**, **OWASP ZAP**, and **Crashtest Security** can easily detect reflected XSS by scanning user inputs and responses.

---

## 2. Stored Cross-Site Scripting (Persistent)

**Stored XSS** occurs when the injected script is **permanently stored** on the server (e.g., in a database or file system). The script is served to users whenever they access the vulnerable content.

### Example Scenario

**`page.php`**

```php
<?php
  echo $_POST['comment']; // Vulnerable
?>
```

### Attack

An attacker submits a comment:

```html
<script>alert('Stored XSS')</script>
```

The comment gets stored in the database. Every time a user loads that comment, the script executes.

### Fix

Sanitize user input before storing or displaying:

```php
echo htmlspecialchars($comment, ENT_QUOTES, 'UTF-8');
```

---

## 3. DOM-Based Cross-Site Scripting

**DOM-based XSS** happens when JavaScript running in the browser takes attacker-controlled input from a source and **writes it to the DOM** without proper sanitization.

### Source and Sink Example

| Source              | Description                     |
| ------------------- | ------------------------------- |
| `document.URL`      | Full URL                        |
| `location.search`   | Query string                    |
| `document.referrer` | Previous page’s URL             |
| `document.cookie`   | User's cookies                  |
| `window.name`       | Metadata for the current window |

| Sink                 | Description                            |
| -------------------- | -------------------------------------- |
| `document.write()`   | Writes to the page                     |
| `element.innerHTML`  | Renders HTML                           |
| `eval()`             | Executes JavaScript                    |
| `setTimeout(string)` | Executes JavaScript string after delay |

---

### Example Scenario

**dashboard.html**

```html
<script>
  if (document.URL.indexOf("context=") > -1) {
    document.write(document.URL.split("context=")[1]);
  }
</script>
```

**Attacker Payload:**

```
https://vulnerable-site.com/dashboard.html?context=<img src=x onerror=alert(1)>
```

When the victim opens the link, it triggers the XSS payload.

### Fix

Use a safe sink and sanitize untrusted input:

```js
const text = document.URL.split("context=")[1];
document.getElementById("output").textContent = text;
```

---

## DOM-Based Vulnerabilities and Corresponding Sinks

| Vulnerability Type           | Example Sink               |
| ---------------------------- | -------------------------- |
| DOM XSS                      | `document.write()`         |
| Open redirection             | `window.location`          |
| Cookie manipulation          | `document.cookie`          |
| JavaScript injection         | `eval()`                   |
| Document-domain manipulation | `document.domain`          |
| WebSocket URL poisoning      | `WebSocket()`              |
| Link manipulation            | `element.src`              |
| Web message manipulation     | `postMessage()`            |
| AJAX header manipulation     | `setRequestHeader()`       |
| Local file-path manipulation | `FileReader.readAsText()`  |
| HTML5 storage manipulation   | `sessionStorage.setItem()` |
| XPath injection              | `document.evaluate()`      |
| JSON injection               | `JSON.parse()`             |
| DOM data manipulation        | `element.setAttribute()`   |
| Denial of Service (DoS)      | `RegExp()`                 |

*Source: [PortSwigger](https://portswigger.net/web-security/dom-based)*

---
