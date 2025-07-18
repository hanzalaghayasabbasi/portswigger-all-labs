# Clickjacking (UI Redressing)

Clickjacking is a **web security vulnerability** that allows an attacker to trick users into clicking on something different from what they perceive. This is typically achieved by overlaying **invisible or disguised UI elements** (like buttons) over legitimate content using `<iframe>` tags.

For example, a user may think they're entering a giveaway to win a luxury cruise, but in reality, they're clicking a button that transfers money to an attacker.

📺 **Video Guide**: [Clickjacking Demonstration](https://youtu.be/OQRYDAG0hGE)

---

## Why Clickjacking Is Dangerous

Clickjacking is often combined with other vulnerabilities to increase impact:

1. **Cross-Site Scripting (XSS)** – Enhances payload injection into frames.
2. **Inadequate Content Security Policy (CSP)** – Allows framing from malicious sites.
3. **Insecure Direct Object Reference (IDOR)** – Can trick users into unintended actions like changing passwords or transferring money.

---

## Mitigation: `X-Frame-Options` Header

To defend against clickjacking, set the `X-Frame-Options` response header.

### Options

| Value           | Description |
|------------------|-------------|
| `DENY`           | Prevents the page from being displayed in any frame. |
| `SAMEORIGIN`     | Allows the page to be framed only by pages on the **same origin**. |
| `ALLOW-FROM URI` | Allows framing only by a **specific trusted URI** (note: limited browser support). |

### Example (Apache)
```apache
Header always set X-Frame-Options "SAMEORIGIN"
````

### Modern Alternative: CSP Header

```http
Content-Security-Policy: frame-ancestors 'none';
```

---

## Testing for Clickjacking Vulnerabilities

You can test using **Burp Suite Professional** with the **Clickbandit tool**, or manually.

### 🔍 Scanning with Burp Suite

1. Open your target page in **Burp's browser** (e.g., the "My account" page).
2. In **Proxy > HTTP history**, right-click the request and select `Do active scan`.
3. Once the scan completes, go to **Dashboard > Issues**.
4. Look for issues titled **"Frameable response"** – this indicates the page is vulnerable.

---

## Exploiting Clickjacking with Clickbandit

[Burp Clickbandit Tool](https://portswigger.net/burp/documentation/desktop/tools/clickbandit)

> You can create a **proof-of-concept** attack using Clickbandit.

### ⚙️ Steps to Use Clickbandit:

1. Open the vulnerable page in Burp's browser.
2. In Burp Suite, go to **Burp > Clickbandit**.
3. Click **Copy Clickbandit to clipboard**.
4. Paste the script into the **DevTools Console** in the browser.
5. Click **Start** to begin recording clicks.
6. Interact with potential targets (buttons, links, forms).
7. Click **Finish** to switch to **Review mode**.
8. Click each UI element in the overlay to verify the attack.
9. Adjust zoom or iframe position using:

   * `+` / `-` to zoom
   * Arrow keys to move
   * Checkbox to disable actions temporarily
10. Click **Save** to download the PoC HTML file (optional).

---

## Tools & Resources

* 🔧 **Burp Clickbandit Tool:**
  [https://portswigger.net/burp/documentation/desktop/tools/clickbandit](https://portswigger.net/burp/documentation/desktop/tools/clickbandit)

* 📖 **Clickjacking (UI Redressing) Guide:**
  [https://portswigger.net/web-security/clickjacking](https://portswigger.net/web-security/clickjacking)

---

## Summary

Clickjacking is a serious threat when paired with other vulnerabilities. Always:

* Prevent embedding using `X-Frame-Options` or CSP
* Use tools like Burp Suite + Clickbandit for automated testing
* Avoid placing sensitive actions behind single-click buttons without confirmation

```
