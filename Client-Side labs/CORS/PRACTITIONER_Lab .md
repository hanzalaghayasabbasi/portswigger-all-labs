## Labs Covered

This write-up focuses on the following **PRACTITIONER-level lab** from the PortSwigger Web Security Academy related to **Cross-origin resource sharing (CORS)**:

**CORS vulnerability with trusted insecure protocols**  
This lab demonstrates how trusting insecure protocols (like HTTP instead of HTTPS) in CORS policies can lead to security vulnerabilities.

---

### LAB 3 - CORS vulnerability with trusted insecure protocols

### Lab Description

![image](https://github.com/user-attachments/assets/2376bbc1-d604-433b-b167-a0f3b1f3db3a)


### Solution
Here's a more professional and structured version of your write-up:

---

## Lab Walkthrough: Exploiting CORS Misconfiguration with XSS to Exfiltrate API Key

### Step-by-Step Guide

1. **Login and Identify the API Key**

   * Access the shop application provided by the lab.
   * Login with the credentials:

     ```
     Username: wiener
     Password: peter
     ```
  ![image](https://github.com/user-attachments/assets/b14f1b82-9afa-4484-af64-63631558f798)

   * Once logged in, navigate to the "My Account" page. The API key for the user `wiener` is visible.
   * Viewing the HTML source reveals a JavaScript call fetching this key dynamically.

     ![image](https://github.com/user-attachments/assets/35165632-ac10-4a0b-beeb-e061a16f3201)


 
   


1. **Review Network Activity**

   * Open the browser's developer tools or Burp Suite to monitor requests.
   * You'll observe a `GET` request to the endpoint:

     ```
     /accountDetails
     ```
   * Send this request to the **Repeater** tab in Burp Suite for testing.
  
      ![image](https://github.com/user-attachments/assets/756ff06b-4bfd-4e29-8127-7392f771f052)

2. **Test for CORS Misconfiguration**

   * Add an `Origin` header to the request:

     ```
     Origin: http://subdomain.0a4f006a04b14c4a807d0dfc00b80015.web-security-academy.net
     ```
   * Replace the domain with the appropriate subdomain for your lab.
   * If the server reflects this origin in the response header:

     ```
     Access-Control-Allow-Origin: http://subdomain.0a4f006a04b14c4a807d0dfc00b80015.web-security-academy.net
     ```

     and includes:

     ```
     Access-Control-Allow-Credentials: true
     ```

     — this confirms the server is **vulnerable to CORS misconfiguration**.


        ![image](https://github.com/user-attachments/assets/a5fb852e-7612-4eec-816f-d92349ec700f)

3. **Find XSS Injection Point**

   * Navigate to any product page and click on **Check Stock**.
   * Intercept the request and inject an XSS payload into the `productId` parameter.
   * If the application executes JavaScript via this parameter, it confirms an XSS vector is present.

     If we enter a simple **alert()** script in productID parameter, we get a pop up which confirms that it is vulnerable to XSS.

```http
GET /?productId=<script>alert("Hey")</script>&storeId=1 HTTP/1.1
Host: stock.0a4f006a04b14c4a807d0dfc00b80015.web-security-academy.net
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:106.0) Gecko/20100101 Firefox/106.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```
![image](https://github.com/user-attachments/assets/227d19db-69c8-4760-b5bd-60b3d9ee8d92)

This **productID** parameter is vulnerable to XSS

4. **Prepare the Exploit Script**

   * Go to the **Exploit Server** provided in the lab.

   * Store the following script (modify URLs accordingly):

     ![image](https://github.com/user-attachments/assets/ac666288-7cc1-4f0d-b20d-1ecebaa59a2b)


   * Replace:

     * `YOUR-LAB-ID` with the lab’s domain.
     * `YOUR-EXPLOIT-SERVER-ID` with your exploit server domain.
    
     * ![image](https://github.com/user-attachments/assets/e2b6edc1-7ca9-40e2-8750-653fed6de339)


5. **Inject the Script via XSS**

   * Use the XSS injection point discovered earlier (e.g., via `productId` in stock checker).
   * Inject the `<script>` tag to trigger the CORS-based API key exfiltration.

6. **Deliver Exploit to Victim**

   * Once the exploit is saved and ready, click **"Deliver exploit to victim"** in the exploit server interface.
   * Go to the **Access Log** tab of the exploit server.

  ![image](https://github.com/user-attachments/assets/a07f1ace-2441-40b2-b6db-9ef8e63cf96a)

7. **Retrieve and Clean API Key**

   * You’ll see a request logged containing the administrator's API key.
   * Use Burp Decoder or a URL decoder to clean and extract the key.
    ![image](https://github.com/user-attachments/assets/d0a0269a-d9b2-476f-a7c8-700757a30c5f)

  
The code is now clean, and here is the API key for the administrator: `7Rdgi0KARqz2GXkaWvspBYozqsoxmOgl.`


 Submit the API key of admin to solve the lab.

![image](https://github.com/user-attachments/assets/e6da60a7-4c8c-4c47-a57a-0615de5445d6)

---

