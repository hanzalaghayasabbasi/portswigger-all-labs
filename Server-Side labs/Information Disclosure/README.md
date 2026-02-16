# Information disclosure vulnerabilities

## Lab Levels

Jump directly to the lab writeups:

* [APPRENTICE](./APPRENTICE_Lab.md)
* [PRACTITIONER](./PRACTITIONER_Lab.md)
  
## Introduction

Information disclosure (or leakage) occurs when a web application unintentionally exposes data that it shouldn’t. This data can be:

* **User-sensitive data:** usernames, email addresses, passwords (even hashed), credit card info, or personal details.
* **Business-sensitive data:** internal reports, pricing strategies, project files, or intellectual property.
* **Technical information:** server software versions, database types, debug logs, API keys, or directory structures.
  
## Common Places Where Sensitive Information May Be Exposed

When assessing a web application for information disclosure vulnerabilities, it's important to know where to look. Below are some common examples of locations and features that may unintentionally reveal sensitive data:

---

### 🔍 1. Files for Web Crawlers
- **robots.txt** and **sitemap.xml** can disclose hidden directories or sensitive endpoints that admins intended to hide from search engines but forgot to secure.

---

### 📁 2. Directory Listings
- Misconfigured servers may expose **directory listings**, allowing anyone to browse files and folders directly through the browser.

---

### 💬 3. Developer Comments
- Developers sometimes leave **comments in HTML or JavaScript**, which may reveal secrets, credentials, or hidden functionalities.

---

### ⚠️ 4. Error Messages
- Detailed **server-side error messages** can disclose paths, configurations, technologies used, or even database queries.

---

### 🐞 5. Debugging Data
- Debug or verbose output may expose internal variables, logic flow, or sensitive data during errors or test modes.

---

### 👤 6. User Account Pages
- User-specific pages may leak **personal information**, session tokens, or other private data if not properly restricted.

---

### 💾 7. Backup Files
- Files such as `config.php.bak`, `db.sql`, or `index.old` may be left on the server and accessible via direct URL guessing.

---

### ⚙️ 8. Insecure Configuration
- Configuration files like `.env`, `.gitignore`, or exposed `config.js` files may contain **credentials or API keys**.

---

### 🕹️ 9. Version Control History
- Exposed `.git/` or `.svn/` directories can allow attackers to download the full codebase and inspect **commit history**, potentially exposing deleted secrets or old vulnerabilities.

---

These weak spots are frequently tested during reconnaissance and enumeration in penetration testing. Identifying and addressing them is essential for securing a web application.
