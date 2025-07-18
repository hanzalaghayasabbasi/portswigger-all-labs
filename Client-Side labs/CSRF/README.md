# Cross-Site Request Forgery (CSRF)

Cross-Site Request Forgery (CSRF) is a web security vulnerability that allows an attacker to trick authenticated users into performing unwanted actions on a web application in which they're logged in.

It circumvents the **Same-Origin Policy** (SOP), which is designed to prevent different websites from interfering with each other’s data.

---

## How CSRF Works

For a CSRF attack to be successful, three key conditions must be met:

1. **A Relevant Action**  
   The application must have an action worth exploiting (e.g., change email, change password, fund transfer).

2. **Cookie-Based Session Handling**  
   The application must use **only cookies** to identify user sessions, and the browser must automatically include those cookies in cross-origin requests.

3. **No Unpredictable Parameters**  
   All request parameters must be predictable or guessable by the attacker (e.g., no current password required to change to a new one).

---

## Example Use Case: Email Change

Most CSRF labs involve exploiting a user's email change functionality. The victim is logged in, and when they click a malicious link (crafted by the attacker), their email gets changed to the attacker’s.

**Important:**  
> A CSRF attack **won’t work** if the user is not authenticated. The browser must send the valid session cookies automatically for the request to be processed.

---

## SameSite Cookie Attribute and CSRF Defense

Modern browsers support the `SameSite` cookie attribute to help mitigate CSRF. Here's how each setting behaves:

### 1. `SameSite=Strict`

- Cookies are sent **only** for requests originating from the same site.
- Prevents all cross-origin requests (including CSRF).
- CSRF attacks will **fail**.

### 2. `SameSite=Lax`

- Cookies are sent for **top-level navigation** (e.g., clicking a link).
- Does not send cookies on embedded content or POST requests from another site.
- CSRF attacks may **partially work**, depending on the method.

**Allowed:**
```html
<a href="https://mywebsite.com/transfer">Transfer</a>
````

**Blocked:**

```html
<img src="https://mywebsite.com/transfer" />
<form action="https://mywebsite.com/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@example.com" />
</form>
```

### 3. `SameSite=None; Secure`

* Cookies are sent for **all cross-site** requests.
* **Must** be marked as `Secure` (HTTPS only).
* CSRF attacks are **possible**.

### 4. **No `SameSite` Attribute**

* Treated as `Lax` by most modern browsers.
* Partial CSRF protection applies.

---

## Visual Behavior Comparison

| SameSite Setting | Cross-Site GET | Cross-Site POST | CSRF Risk |
| ---------------- | -------------- | --------------- | --------- |
| Strict           | ❌ Blocked      | ❌ Blocked       | ❌ No      |
| Lax              | ✅ Partial      | ❌ Blocked       | ⚠️ Medium |
| None             | ✅ Allowed      | ✅ Allowed       | ✅ Yes     |
| Not Set          | ✅ Partial      | ❌ Blocked       | ⚠️ Medium |

---


## References

* [PortSwigger: Cross-site request forgery](https://portswigger.net/web-security/csrf)
* [MDN Web Docs: SameSite cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)

