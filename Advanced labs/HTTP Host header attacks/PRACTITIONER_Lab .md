## Labs Covered

This write-up focuses on the following **PRACTITIONER-level labs** from the PortSwigger Web Security Academy related to **Host Header Attacks and related HTTP parsing vulnerabilities**:

**3 Web cache poisoning via ambiguous requests**  
<blockquote>
This lab demonstrates how ambiguous HTTP requests can be used to poison web caches and serve malicious content to users.
</blockquote>
	
**4 Routing-based SSRF**  
<blockquote>
This lab shows how improper routing based on Host headers can lead to Server-Side Request Forgery (SSRF) vulnerabilities.
</blockquote>

**5 SSRF via flawed request parsing**  
<blockquote>
This lab demonstrates how flawed parsing of HTTP requests can be exploited to perform SSRF attacks.
</blockquote>

**6 Host validation bypass via connection state attack**  
<blockquote>
This lab demonstrates how attackers can bypass host validation mechanisms by manipulating connection states.
</blockquote>

---

### LAB 3 - Web cache poisoning via ambiguous requests

### Lab Description

<img width="893" height="326" alt="image" src="https://github.com/user-attachments/assets/498d2b65-f834-40af-839f-38e65b814bba" />

### Solution
Firstly, send a request to the `“/”` endpoint and observe the behavior. Everythings as it expected. Next, let’s proceed to manipulate the host header and analyze the response.

<img width="1875" height="608" alt="image" src="https://github.com/user-attachments/assets/6796bdb7-d544-4aad-99d8-cfcfee4bd8c9" />


Also we can see that manipulated host header give us error in and reflected in reponse

<img width="1875" height="608" alt="image" src="https://github.com/user-attachments/assets/a950989d-889a-455b-b760-a17534153252" />


Randomly add **:90** and I can see tha  **Xcachehit, age,Cache control**  header and our host is also reflected in reponse


<img width="1822" height="812" alt="image" src="https://github.com/user-attachments/assets/1ba5b7cf-9d02-42e1-8f75-3ab475b309e6" />




As you can observe, when a malformed Host header is used, it is reflected in the response body with a 504 response code. I attempted various methods such as adding a port or using single quotes, but I was unable to modify the response. Whatever I typed in the Host header was reflected in the response exactly. The next testing approach is duplicating the Host header, which seems OK given the lab’s name. However, it’s crucial to monitor the **Age** and **X-Cache headers** for the cache mechanism. These headers can provide valuable insights during the attack.

• **Cache-Control:** max-age=30: This tells browsers to cache the content for up to 30 seconds before checking with the server for an update.
 
• **Age: 17:** This indicates the content has been in the server's cache for 10 seconds.
 
• **X-Cache: hit:** This is likely a custom header from the server software, informing you that the content was retrieved from the server's cache (not freshly generated).


<img width="1900" height="669" alt="image" src="https://github.com/user-attachments/assets/e34148da-d067-45ef-9df6-f8571daa1301" />




So we have send this request   `Host: test.net”></script><script>alert(1)</script>` in host,and  I can see that alert is reflected in reponse


**Note: you have to send request multiple time due to cache used by server**


<img width="1884" height="621" alt="image" src="https://github.com/user-attachments/assets/7d277e10-b2f3-4bf1-af55-f058d5dfd842" />




And we can see reponse of  above request in our browser


<img width="1612" height="529" alt="image" src="https://github.com/user-attachments/assets/3bcfa652-5368-40f5-a56b-12864bc9f7d0" />



To solve the lab we have to alert cookie then lab is solved

<img width="1884" height="648" alt="image" src="https://github.com/user-attachments/assets/7cf6754d-9c7c-4af3-bad7-62411e950ac3" />



And we can see the alert in reponse of documet.cookie and then lab is solved

<img width="1727" height="410" alt="image" src="https://github.com/user-attachments/assets/17d69638-7e63-4d4d-9962-eb4956c6373b" />


---

### LAB 4 - Routing-based SSRF

### Lab Description

<img width="929" height="578" alt="image" src="https://github.com/user-attachments/assets/b6de0dc8-fff0-4cdf-b625-78fb6abb38a4" />

### Overview: Accessing Internal Websites with Virtual Host Brute-Forcing & Routing-Based SSRF

#### 1. Virtual Host Brute-Forcing

Some companies host both public and private/internal websites on the same server. Although the internal hostname might resolve to a **private IP address**, attackers can still access these internal virtual hosts if they can guess the hostname.

**Example scenario:**

* `www.example.com` → `12.34.56.78` (public)
* `intranet.example.com` → `10.0.0.132` (private)

Even if there is no public DNS record for `intranet.example.com`, it may still be reachable by directly sending HTTP requests with a `Host` header set to the guessed name.

**Attack technique:**

* Use tools like **Burp Intruder** to brute-force hostnames.
* Use a wordlist of common subdomains (e.g., `admin`, `internal`, `dev`, `portal`, `intranet`).
* Send requests to the target server, modifying the `Host` header with each candidate.

This technique helps identify hidden applications that are not meant to be externally accessible.

---

#### 2. Routing-Based SSRF (Host Header SSRF)

**Routing-based SSRF** occurs when reverse proxies or load balancers route traffic based on the `Host` header, and the server does not validate or restrict it properly.

**Key targets:**

* Load balancers
* Reverse proxies
* Internal routing systems

These intermediaries may forward requests based on the `Host` header value, which an attacker can manipulate to route the request to internal-only services or other unintended systems.

**How the attack works:**

1. Attacker crafts an HTTP request with a custom `Host` header, such as:

   ```
   Host: internal.example.local
   ```
2. If the intermediary component uses the `Host` header for routing, it may forward the request to the internal service.
3. This gives the attacker indirect access to internal services.

**Detection:**

* Use **Burp Collaborator** to detect external interactions.
* Set the `Host` header to a Burp Collaborator domain.
* If the server performs a DNS lookup or HTTP request to this domain, SSRF via the `Host` header is likely possible.

---

#### 3. Accessing Internal IP Addresses

Once you've confirmed that routing-based SSRF is possible, the next step is to target internal IPs.

**Ways to find internal IPs:**

* Look for internal IP leaks in HTTP responses or JavaScript.
* Check if internal hostnames resolve to private IPs.
* Brute-force common internal IP ranges using tools or manual requests.

**Common private IP ranges:**

* `10.0.0.0/8` → 10.0.0.0 to 10.255.255.255
* `172.16.0.0/12` → 172.16.0.0 to 172.31.255.255
* `192.168.0.0/16` → 192.168.0.0 to 192.168.255.255

---

#### CIDR Notation Quick Summary

CIDR notation describes IP address ranges using this format:
`<base IP>/<prefix length>`

* `10.0.0.0/8` = all IPs starting with 10.x.x.x
* `192.168.0.0/16` = all IPs from 192.168.0.0 to 192.168.255.255

---



### Solution

There’s not much to see but a `/GET` call to request the home page.


<img width="1894" height="675" alt="image" src="https://github.com/user-attachments/assets/ba2754af-42a9-47ee-94a8-ad3762fb7178" />


Now, let's check for host header injection by entering any other Hosts in the field. Let’s enter our burp collaborator’s IP to listen for any request that is made from the web application.

On doing so, we got a `200 OK`response from the server. 

<img width="969" height="417" alt="image" src="https://github.com/user-attachments/assets/5a576df9-b406-4305-b86f-01d1acbcb4df" />


Let’s check what our collaborator has received.

DNS request

<img width="1402" height="569" alt="image" src="https://github.com/user-attachments/assets/680214e3-ca2c-4d61-a5e6-464f9f52fb3b" />


Now looking at http request we can see that  the application tried to fetch our collaborator IP which is the Host that we provided. So, we could verify that the application was vulnerable to host header injection.


<img width="1101" height="618" alt="image" src="https://github.com/user-attachments/assets/a06dde23-4c8b-4350-9be7-054aeb803dbd" />






Now, let’s try to perform SSRF leveraging this host header injection attack. Here, we can FUZZ the internal IP in the host field to figure out where the application is running. In a real world scenario, we can fuzz all **A**, **B** and **C** classes of private IP to determine the location of the service running internally. However, in this lab we are provided that the admin page is hosted within `192.168.0.0/24` network. The /24 range contains total of **256** IPs. So, let's take the request to the burp’s intruder and fuzz the whole range of `/24` subnet.



<img width="1920" height="455" alt="image" src="https://github.com/user-attachments/assets/6d715b0b-7181-451d-ba96-b3e3d2155a9b" />



Select the Numbers List up from `0 to 255` (256 iterations) as payload and start the attack.



<img width="652" height="536" alt="image" src="https://github.com/user-attachments/assets/aa534469-d0c7-48da-b0b8-4afee153b9db" />



As we can see that 206 last adress ip is redirecting us


<img width="721" height="441" alt="image" src="https://github.com/user-attachments/assets/e3e35518-9e70-4b29-9632-276e50843702" />


<img width="741" height="439" alt="image" src="https://github.com/user-attachments/assets/a3b3597e-7217-433e-8986-6a0c609287a5" />




Now using internal ip and going to **/admin** will reveal the admin panel


<img width="1184" height="435" alt="image" src="https://github.com/user-attachments/assets/da0bf0c9-ea69-4f10-abcc-abba8dec0f0c" />



In the admin page we could see a user deletion form. Sending POST request to `/admin/delete` with the csrf token and username parameter could delete any user. This is how we could perform SSRF leveraging the host header injection.


<img width="934" height="443" alt="image" src="https://github.com/user-attachments/assets/dbe063e6-4bf6-4b09-b94c-c2916c0d0b0a" />



Finally, the request to delete the user is sent, and the user is deleted. We were able to forge the request on behalf of the application or the server to perform unauthorized and high-privilege actions. This is how we can perform SSRF by chaining it with host header injection.and then lab is solved.


<img width="1626" height="353" alt="image" src="https://github.com/user-attachments/assets/7ed0728a-bb0d-469b-bd8d-c13aa8a43366" />


---

### LAB 5 - SSRF via flawed request parsing

### Lab Description

<img width="897" height="555" alt="image" src="https://github.com/user-attachments/assets/355d1cd6-3386-4419-87d0-13e9057a74fb" />

### Solution


Send the **GET /** request and intercept it received a **200** response to Burp Repeater

<img width="1870" height="639" alt="image" src="https://github.com/user-attachments/assets/fa49017d-35b1-4fe0-9668-3216116bd7a8" />


We can see in below image website validates the Host header and blocks any requests in which it has been modified.

<img width="1873" height="560" alt="image" src="https://github.com/user-attachments/assets/1c1c55b3-a3af-4cfa-9945-8f1c35d564f9" />


Observe that we can also access the home page by supplying an absolute URL in the request line as follows:
GET `https://YOUR-LAB-ID.web-security-academy.net/`

<img width="1870" height="622" alt="image" src="https://github.com/user-attachments/assets/c05d732d-e9f4-4afe-9411-44eda8ebc2ea" />



Notice that when you do this, modifying the Host header no longer causes your request to be blocked. Instead, you receive a timeout error. This suggests that the absolute URL is being validated instead of the Host header.
Use Burp Collaborator to confirm that you can make the website's middleware issue requests to an arbitrary server in this way. For example, the following request will trigger an HTTP request to your Collaborator server:
**GET https://YOUR-LAB-ID.web-security-academy.net/**
**Host: BURP-COLLABORATOR-SUBDOMAIN**


<img width="1561" height="614" alt="image" src="https://github.com/user-attachments/assets/15603ac2-d959-4bc9-bebb-6f81cf6806b5" />



We can see that above url  is sending request to our server

<img width="1173" height="676" alt="image" src="https://github.com/user-attachments/assets/1ca8478e-7ae9-4e4c-916f-8014a11d1451" />

Use the Host header to scan the IP range `192.168.0.0/24` to identify the IP address of the admin interface. Send this request to Intuder
And we can see that in beloiw image `137` stand out valid internal ip

<img width="964" height="527" alt="image" src="https://github.com/user-attachments/assets/cabbd99e-86af-4353-af85-7c839dd92e3f" />



We can see that it is redirecting us to `/admin`


<img width="1014" height="585" alt="image" src="https://github.com/user-attachments/assets/c02e95ed-618a-417f-8f23-7d48acb4670e" />


In Burp Repeater, append **/admin** to the absolute URL in the request line and send the request. Observe that we now have access to the admin panel, including a form for deleting users.
and we have used internal ip in host header

<img width="1810" height="745" alt="image" src="https://github.com/user-attachments/assets/6fdf2f1b-6ddb-4e6c-8ec7-446ddd74a033" />


Change the absolute URL in your request to point to /admin/delete. Copy the CSRF token from the displayed response and add it as a query parameter to your request. Also add a username parameter containing carlos. The request line should now look like this but with a different CSRF token:

```
GET https://YOUR-LAB-ID.web-security-academy.net/admin/delete?csrf=QCT5OmPeAAPnyTKyETt29LszLL7CbPop&username=carlos
```
Copy the session cookie from the Set-Cookie header in the displayed response and add it to your request.
Right-click on your request and select "Change request method". Burp will convert it to a POST request.
Send the request to delete carlos and solve the lab.

<img width="1369" height="577" alt="image" src="https://github.com/user-attachments/assets/bf7cceb0-afac-4d84-801a-614663164d75" />

<img width="1600" height="270" alt="image" src="https://github.com/user-attachments/assets/f557efe9-9b80-40f0-841d-5ddf47d86a9a" />

---

### LAB 6 - Host validation bypass via connection state attack

### Lab Description

<img width="899" height="568" alt="image" src="https://github.com/user-attachments/assets/271ac839-8d85-4a24-a190-532875ff6744" />

### Solution


Now, we can try to modify the Host HTTP header in Burp Repeater:

CHANGE HOST HEADER TO `TEST.COM`

<img width="1515" height="453" alt="image" src="https://github.com/user-attachments/assets/55a931b7-60a4-41f5-97f1-fbaf7d75e91b" />


However, it redirects me to the lab domain.
**What if I supply multiple Host header?**

<img width="1368" height="501" alt="image" src="https://github.com/user-attachments/assets/022f5e2e-739a-466a-806e-fa43c845c3df" />


Duplicate header names are not allowed.
**How about indenting HTTP headers with a space character?**


<img width="1439" height="452" alt="image" src="https://github.com/user-attachments/assets/adb0c3ea-cb60-4bb2-bda2-97799527fc42" />



Hmm… Still the same.
**In the lab’s background, it said:**
	**Hmm… What if I send a normal Host header on the first request, then in the second request I send a malicious Host header, which points to 192.168.0.1?**
	To do so, I’ll use 2 Burp Repeater tabs:
	


This lab is vulnerable to **routing-based** SSRF via the Host header. Although the front-end server may initially appear to perform robust validation of the Host header, it makes assumptions about all requests on a connection based on the first request it receives.


• Tab 1: GET /, normal Host header:

<img width="1577" height="534" alt="image" src="https://github.com/user-attachments/assets/a9fd27db-7d66-46e8-82fc-b2172bd87c79" />

• Tab 2: GET /admin, Host header change to 192.168.0.1:

<img width="1183" height="493" alt="image" src="https://github.com/user-attachments/assets/1fd1a187-883b-4568-afa0-c4625bdf1a8d" />

• Add both tabs to a new group:
	


<img width="1576" height="757" alt="image" src="https://github.com/user-attachments/assets/d023c474-8e4f-4fd5-9513-6238db05442b" />

	
	
<img width="1625" height="556" alt="image" src="https://github.com/user-attachments/assets/866d7b30-de4b-4825-bdcb-102ae061150d" />

	
Change the send mode to Send group in sequence (single connection):
		
<img width="1461" height="518" alt="image" src="https://github.com/user-attachments/assets/21fa772d-135d-4d27-a6ff-98a37681791c" />
	
	
Change the Connection header to **keep-alive**:


<img width="1539" height="552" alt="image" src="https://github.com/user-attachments/assets/f87cbf92-c431-49ab-92ce-51fd0003bb0c" />

	
	
Click Send group **(single connection)**:

<img width="1610" height="626" alt="image" src="https://github.com/user-attachments/assets/b0b02b6c-29c6-48d8-87d8-5424222bd22c" />

	
you can see, the second request has successfully accessed the admin panel!
Now, in order to delete user carlos, we need to send a POST request to `/admin/delete`, with parameter csrf, and username.
Let’s modify the second tab:

• Change the location to `/admin/delete`:
		
<img width="1536" height="683" alt="image" src="https://github.com/user-attachments/assets/65dc5e7a-cf2d-4e23-8458-041884f1e1d2" />


	
Now we can see in below image respones highlighted that to delete user carlso we have to submit post request with csrf and username
		
<img width="1557" height="416" alt="image" src="https://github.com/user-attachments/assets/3002baf5-5ab5-401a-8242-d5ccc197400b" />

	

And now carlos useor is deleted and lab is solved it is giving us **302**
	
<img width="1225" height="502" alt="image" src="https://github.com/user-attachments/assets/eb8f8830-85a3-41d4-9656-8e62ad602bf2" />

	
**Note:**
	
Above request will not work until change request to get and show all the csrf and username in front of get 
i am stuck here

<img width="1258" height="547" alt="image" src="https://github.com/user-attachments/assets/1ed0f43a-7563-4f69-b825-f799acf84c76" />

<img width="1651" height="340" alt="image" src="https://github.com/user-attachments/assets/e6e0719c-48b6-4f20-9b7a-c8ef749fbc73" />



---

