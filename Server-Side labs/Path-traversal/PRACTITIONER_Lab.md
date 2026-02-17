## Labs Covered

This write-up focuses on the following **PRACTITIONER-level labs** from the PortSwigger Web Security Academy:

 **2 File path traversal, traversal sequences blocked with absolute path bypass**  
     <blockquote>
     This lab demonstrates how attackers can bypass basic traversal sequence blocking by supplying absolute paths instead of relative traversal patterns.
     </blockquote>

**3 File path traversal, traversal sequences stripped non-recursively**  
   <blockquote>
  This lab shows how flawed sanitization that strips traversal sequences only once (non-recursively) can be bypassed by chaining multiple traversal sequences.
   </blockquote>

**4 File path traversal, traversal sequences stripped with superfluous URL-decode**  
  <blockquote>
  This lab demonstrates how attackers can leverage multiple layers of URL encoding to bypass sanitization logic that strips traversal sequences after decoding.
  </blockquote>

 **5 File path traversal, validation of start of path**  
   <blockquote>
  This lab shows how poorly implemented checks that validate only the start of a file path can be bypassed to access unauthorized files.
   </blockquote>

 **6 File path traversal, validation of file extension with null byte bypass**  
   <blockquote>
  This lab demonstrates how attackers can use null byte injection to bypass file extension validation and retrieve unauthorized files.
   </blockquote>

---

## LAB 2 - File path traversal, traversal sequences blocked with absolute path bypass

### Lab Description :

![image](https://github.com/user-attachments/assets/5b73afb6-2efa-4fe0-b28c-bc4ac78d0cd6)

### Overview
![image](https://github.com/user-attachments/assets/f96c4ccf-a95e-4cdd-b010-3ec2f324bfe0)


### Solution :

To retrieve an image the application uses a GET request with the parameter filename:


![image](https://github.com/user-attachments/assets/83a22a87-ec41-4895-be92-774c02c22eb5)


To retrieve the contents of `/etc/passwd`, send the following request:

```

GET /image?filename=/etc/passwd

```
![image](https://github.com/user-attachments/assets/38fe4ecb-8657-4ed2-a159-844936b438cc)


Lab is solved

![image](https://github.com/user-attachments/assets/e702956b-aaf4-4fe9-aa92-14f1c5ab80a9)


---

## LAB 3 - File path traversal, traversal sequences stripped non-recursively

### Lab Description :

![image](https://github.com/user-attachments/assets/b7482dcb-211d-40a8-9ebd-e919851464b7)


### Solution :

When the webpage loads, it loads all the images. The captured request looks like this,

![image](https://github.com/user-attachments/assets/793dd631-1975-4ca3-a206-3857fd7a000b)

![image](https://github.com/user-attachments/assets/6744dca5-828c-467d-aac8-ff4478efba27)

when we try this payload - ..././..././..././..././..././etc/passwd HTTP/2 , we get the contents of the file.

![image](https://github.com/user-attachments/assets/c5a93a72-276f-4307-b172-d5389ac96b09)


Lab is solved
![image](https://github.com/user-attachments/assets/63f7e1a9-a4c9-40d9-9d3a-0144942f6042)

---

## LAB 4 - File path traversal, traversal sequences stripped with superfluous URL-decode

### Lab Description :

![image](https://github.com/user-attachments/assets/ecdfe2d5-f986-4974-b535-2b5d5d77d357)

### Solution :

The request which loads images loooks like ,

![image](https://github.com/user-attachments/assets/7202de74-457a-43fa-ab4c-0e4b1e4d0ca7)

To retrieve **/etc/passwd** we need to use double URL encode the characters:

````
GET /image?filename=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd

````
![image](https://github.com/user-attachments/assets/b8e4736a-aa62-447e-9e27-4ac5759b8233)



Lab is solved

![image](https://github.com/user-attachments/assets/d71e53a4-4cfa-4769-bf0b-008f1fa137a6)

---

## LAB 5 - File path traversal, validation of start of path

### Lab Description :

![image](https://github.com/user-attachments/assets/ac69399d-b52f-4b29-96b6-1609ea0b506b)


### Solution :


If an application requires that the user-supplied filename must start with the expected base folder, such as `/var/www/images`, then it might be possible to **include the required base folder followed by suitable traversal sequences** to access restricted files.

For example:

```bash
filename=/var/www/images/../../../etc/passwd
````

In this lab, the website loads several images just like the previous labs.
The request captured looks like this:

![image](https://github.com/user-attachments/assets/8f3abbf6-daca-460c-b2bd-1024e4c3beeb)


To retrieve `/etc/passwd`, we need the path to start with `/var/www/images/` as required by the server.

Use the following request:

```

GET /image?filename=/var/www/images/../../../etc/passwd

```
![image](https://github.com/user-attachments/assets/b7cb6bae-6b97-47e4-b463-f9e4ac8fb569)


Lab is solved

![image](https://github.com/user-attachments/assets/bb255010-bac9-4221-9ffa-7dd51bc5093a)

---

## LAB 6 - File path traversal, validation of file extension with null byte bypass

### Lab Description :

![image](https://github.com/user-attachments/assets/b4e61e8b-2b0b-402c-b0dc-80d3d99a7050)

### Solution :


If an application requires that the user-supplied filename must end with an expected file extension, such as `.png`, then it might be possible to use a **null byte** to effectively terminate the file path before the required extension.

For example:

```bash
filename=../../../etc/passwd%00.png
````

> **Note:** `%00` is a **null byte** used to terminate a string in certain programming languages. When used in URL input, it can trick the application into treating the input as a different file type, bypassing the extension check.

The captured request which loads images on the website looks like this:

![image](https://github.com/user-attachments/assets/9fddc17a-7d20-4126-80a5-68e4070db96f)



Here, like all the previous labs, it loads a *.jpg* image.

If we give  normal payload like `../../../etc/passwd` , it will give us a **400 Bad Request** in return . 

This is because there is a security implementation being imposed here. The server only accepts i/p's which end with a .jpg file extension.

So we craft a payload in such a way that the payload  we send must satisfy the condition of the server & also retreive the **/etc/passwd** also.

So the final payload will be `../../../etc/passwd%00.png`

![image](https://github.com/user-attachments/assets/1f10f035-caa6-4e4e-979a-ae938648b293)

Lab is solved

![image](https://github.com/user-attachments/assets/7c2e593d-0fd9-4b22-b8c5-8c5927908f11)

---


