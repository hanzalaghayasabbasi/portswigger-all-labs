## Labs Covered

This write-up focuses on the following **APPRENTICE-level labs** from the PortSwigger Web Security Academy related to **Server-side request forgery (SSRF)**:

**Basic SSRF against the local server**  
This lab demonstrates how attackers can exploit SSRF vulnerabilities to send requests to the local server and access internal resources.

**Basic SSRF against another back-end system**  
This lab shows how SSRF can be used to interact with other back-end systems connected to the target server.

---

### LAB 1 - Basic SSRF against the local server

### Lab Description

![image](https://github.com/user-attachments/assets/9884dcb9-4565-48fc-a41e-6e19165ad819)


### Solution




   I began by accessing the lab and navigating to any product page.

  ![image](https://github.com/user-attachments/assets/98120453-62fd-4910-af35-f57a98a4e8e3)




   Using **Burp Suite**, I intercepted the request triggered by the "Check Stock" button.  
   It was sending a request to the internal `stockApi` endpoint to check stock availability.

   ![image](https://github.com/user-attachments/assets/bd9c0ca1-2e0b-4877-925d-3fb5cc031800)


   I replaced the stock URL with:
```

http://localhost/admin

```
This tested whether the internal admin interface was accessible.

![image](https://github.com/user-attachments/assets/99f2f01b-26b3-498e-a967-982f7b6e6cd8)


We get a `200 ok` response & the admin page of the backend server hosted at localhost.

![image](https://github.com/user-attachments/assets/1c31b165-c16d-47ca-bf85-0d425f1aefb3)


Now delete the user carlos to solve the lab.

> If we click the link to delete the user carlos , we won't be able to perform the action. The application throws an error - ` Admin interface only available if logged in as an administrator, or if requested from loopback `

So in the captured request we provide the **uri to delete the user carlos**


I appended the above endpoint to the body of the stock API request:


```http
POST /product/stock HTTP/1.1
Host: target-site.com
...

stockApi=http://localhost/admin/delete?username=carlos
````

Sending this request triggered a server-side request to the admin interface, deleting the user carlos.

![image](https://github.com/user-attachments/assets/701bfcc5-a392-4bfa-97c9-c33b31ad151a)


Thus we've solved the lab.
 

![image](https://github.com/sh3bu/Portswigger_labs/assets/67383098/32891d4d-d155-4673-bee2-17b4b2ad793b)


---

### LAB 2 - Basic SSRF against another back-end system

### Lab Description

![image](https://github.com/user-attachments/assets/6b4251b6-a71a-4a1f-8678-59c5f6857be0)

### Solution


### Steps to Solve

1. **Intercepted the Stock Check Request**

   I accessed the lab and intercepted the stock check feature using **Burp Suite**.  
   The request included a `stockApi` parameter which the server used to fetch internal product stock information.

   ![image](https://github.com/user-attachments/assets/8bb0ff14-1ee7-46e8-8062-0725c40caf53)


2. **Initiated an Internal IP Scan with Intruder**

   To find the internal admin panel, I configured **Burp Intruder** to brute-force the final octet (`X`) in the IP range `192.168.0.X`.  
   The payload positions were set on:
      ```

      http://192.168.0.\[1-255\]:8080/admin

    ```
   

![image](https://github.com/user-attachments/assets/75ea40ab-b01a-458a-9411-9ecc8e1a7ff8)

We got a 200 ok response for 23. So the ip of backend server is 192.168.0.23.

![image](https://github.com/user-attachments/assets/df9ce912-2546-4ef6-adb9-b67a775d1487)


3. **Identified the Admin Interface**

After scanning, I found that the admin interface was located at:
 ```

   [http://192.168.0.23:8080/admin
   
  ```
 Visiting this endpoint through the `stockApi` parameter returned a `200 OK` response, along with a `/delete?username=carlos` endpoint in the body.

![image](https://github.com/user-attachments/assets/a89269bd-f6c7-489b-8804-b77c9cd77a09)


4. **Deleted the User via SSRF**

I appended the delete endpoint in the `stockApi` parameter:

 ```

   http://192.168.0.23:8080/admin/delete?username=carlos
 
```
and sent the request.

![image](https://github.com/user-attachments/assets/ac0678e8-3782-4171-8344-f6d822b399db)


5. **Lab Solved**

The server processed the internal request and deleted the user `carlos`, successfully completing the lab.


![image](https://github.com/user-attachments/assets/4cfb630e-7ff7-4964-ba71-3c89fd84ee0f)


---
