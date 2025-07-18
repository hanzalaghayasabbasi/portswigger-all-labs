## Labs Covered

This write-up focuses on the following **EXPERT-level labs** from the PortSwigger Web Security Academy related to **Web Cache Poisoning**:

**Web cache poisoning to exploit a DOM vulnerability via a cache with strict cacheability criteria**  
This lab demonstrates how an attacker can leverage strict caching rules to poison cache responses that trigger DOM-based vulnerabilities in clients.

**Combining web cache poisoning vulnerabilities**  
This lab shows how attackers can chain multiple cache poisoning vulnerabilities together to create a more reliable or severe attack.

**Cache key injection**  
This lab demonstrates how injecting characters into the cache key allows attackers to manipulate which responses get cached.

**Internal cache poisoning**  
This lab explores poisoning internal server-side caches that are not directly accessible to external users but influence backend behavior.

---

### LAB 10 - Web cache poisoning to exploit a DOM vulnerability via a cache with strict cacheability criteria

### Lab Description
<img width="850" height="387" alt="image" src="https://github.com/user-attachments/assets/c681320b-e8e4-4d60-916c-24652aa30bac" />

### Solution

First we will looK AT Normal REQUEST WE CAN SEE THAT HOST Come Inside Script in json.

<img width="1150" height="402" alt="image" src="https://github.com/user-attachments/assets/303b37a9-711f-460c-8c84-4a72b06ace76" />

Manipulating host header gives us error.

<img width="1876" height="511" alt="image" src="https://github.com/user-attachments/assets/6a236352-1324-47e7-bf01-d57248be0f87" />

Next I have launch param Miner to brute force header and I have find
**X-forwarded-host** I will used this to change host header

<img width="1007" height="405" alt="image" src="https://github.com/user-attachments/assets/0073823b-3e49-49a9-b8ce-5d45c484b8dc" />


We can see that adding **x-forwarded-host** gives us the reponse website of that header

<img width="1867" height="536" alt="image" src="https://github.com/user-attachments/assets/a0dafe7b-7392-424b-bb62-3d0506dc8096" />

We  have seen that `/resources/js/geolocate.js` we can also used network tab in console to see these request


<img width="1916" height="699" alt="image" src="https://github.com/user-attachments/assets/867e827b-6bc9-4853-816c-db1d0b21d526" />


The below is full code of `/resources/js/geolocate.js`


<img width="1212" height="470" alt="image" src="https://github.com/user-attachments/assets/01072471-b952-40a2-ac0e-7035abd46f9b" />


We can see that **initgeolocation function** taking json url and pastiung in div.

<img width="815" height="170" alt="image" src="https://github.com/user-attachments/assets/93e7c9df-2856-4ac8-9fcc-076d5b2b32b7" />


Reloading url and looking at network tab we can see that gelocation is requestion json file.


<img width="1907" height="615" alt="image" src="https://github.com/user-attachments/assets/54879099-cc2d-4b58-8015-1b63fa175124" />

The response of above json file.

<img width="1573" height="652" alt="image" src="https://github.com/user-attachments/assets/8d0658a7-3514-41c0-b169-63ba1a4b7a8f" />

Now in exploit server we have done three thing

Add **/resources/json/geolocate.json** (because website is fetching request from this file from server)
Add **Access-Control-Allow-Origin:*** ( So any other website request resources from over server)
 Add 
 
```
{ "country": "<img src=1 onerror=alert(document.cookie) />" } (to genrate alert)

```

<img width="1445" height="789" alt="image" src="https://github.com/user-attachments/assets/fba2863e-ac8f-4e1e-9895-8ac004a5bbcc" />



Now we have set ou exploit server we will chang `x-forwarded-host` to our exploit server url.


<img width="1851" height="705" alt="image" src="https://github.com/user-attachments/assets/1b8b4d77-c466-441a-90a4-06209cc672d5" />

And we can see that json is loading from our server and it gnerate alert when any other user request from cache


<img width="1478" height="830" alt="image" src="https://github.com/user-attachments/assets/9ddb5e17-9db0-480e-b170-6864cc843fb5" />


We can see in below image now our json file of application has our xss script


<img width="1036" height="167" alt="image" src="https://github.com/user-attachments/assets/5d268e3f-4cf2-4fd8-8689-38b2ac93470d" />

Now lab is solved


<img width="1572" height="335" alt="image" src="https://github.com/user-attachments/assets/a99a97cd-0fb0-43a6-9f1e-a549fced115b" />



---

### LAB 11 - Combining web cache poisoning vulnerabilities

### Lab Description

<img width="868" height="301" alt="image" src="https://github.com/user-attachments/assets/85503b66-c5c3-4608-bb25-51c6611e8fbe" />

### Solution

Website look like can be seen in images  below we have option of changing language from english,arabic,esponal e.t.c

<img width="1694" height="518" alt="image" src="https://github.com/user-attachments/assets/30e40734-9798-427b-8d60-bbf1be392425" />


Trying manipulating header doesnot give me anything,When I look at network request and look for requests comes to us, we can see that we have **translation.js** and **translation.json**



<img width="1223" height="609" alt="image" src="https://github.com/user-attachments/assets/7dea3a83-b146-4bcf-8ef1-cba047e7b02e" />


Below is full code of translation.js


Notice that the website is vulnerable to DOM-XSS due to the way the `initTranslations()` function handles data from the JSON file for all languages except English.


<img width="1359" height="674" alt="image" src="https://github.com/user-attachments/assets/68eea0c8-7450-4f05-b376-f20e024688f0" />

**Translation.json.**



 While I am changing language I notice that it take two request to change
 first is `/setlang/en`
 second is `/?localized=1`


<img width="1870" height="298" alt="image" src="https://github.com/user-attachments/assets/e21da37f-fa40-4bef-91d9-e753518e0ad1" />

When I send first request I see it is **setting** language in cookie


<img width="674" height="36" alt="image" src="https://github.com/user-attachments/assets/48174730-72a4-4951-a620-ae3b69799da5" />

In second request I can see that `lang=es` is setting.



<img width="1797" height="491" alt="image" src="https://github.com/user-attachments/assets/7b5512b4-fe21-40e9-b428-34f8e2bece4a" />



Now using param miner to identify header.

<img width="1233" height="551" alt="image" src="https://github.com/user-attachments/assets/a50e8dfd-57f7-40e6-8925-4d29b39c0714" />




I have also run param miner to identify second parameter.


<img width="1485" height="641" alt="image" src="https://github.com/user-attachments/assets/71027f21-f50f-4f12-a261-c997928039fb" />


We can see below in param miner output it has identfied header

For first request it has identified `X-Orignal header`
For secnd request it has identfied `X-Forwarded-host`

<img width="1125" height="710" alt="image" src="https://github.com/user-attachments/assets/75cff326-c5c7-4e25-b72c-dd628f6cb36a" />

 `X-Original-URL` can be used to change the path of the request, so you can explicitly set /setlang/es. However, you will find that this response cannot be cached because it contains the Set-Cookie header

 <img width="1538" height="543" alt="image" src="https://github.com/user-attachments/assets/41b66ce9-78b5-4af3-8c51-7c2693c9c489" />

Observe that the home page sometimes uses backslashes as a folder separator. Notice that the server normalizes these to forward slashes using a redirect. Therefore, **X-Original-URL: /setlang\es** triggers a 302 response that redirects to /setlang/es. Observe that this 302 response is cacheable and, therefore, can be used to force other users to the Spanish version of the home page.

<img width="1129" height="430" alt="image" src="https://github.com/user-attachments/assets/e31dc553-3561-428b-85e0-c861b7430bc8" />

Configuation of our exploit server

<img width="1467" height="735" alt="image" src="https://github.com/user-attachments/assets/24c96470-bdee-48a9-bd34-b02962e73f42" />

First, poison the `GET /?localized=1` page using the `X-Forwarded-Host header` to import your malicious JSON file from the exploit server.

 <img width="1784" height="617" alt="image" src="https://github.com/user-attachments/assets/8ea4e0df-b594-4cce-94da-47cfbd76ecc3" />

Now, while the cache is still poisoned, also poison the `GET /` page using `X-Original-URL: /setlang\es` to force all users to the Spanish page.

<img width="1374" height="717" alt="image" src="https://github.com/user-attachments/assets/ac517b8d-739e-4002-8cbe-2c2e0756f608" />

Now first we send this request so it will cache es for all the user I Have remove /setlan/es from
get header because i want to change it for all the user in cache,Then after this I will send localized 
Request and relaod page lab is solved.

<img width="1374" height="717" alt="image" src="https://github.com/user-attachments/assets/c292f69e-0088-42a8-9f6d-31e4a2a58a6b" />



Looking after reloading jspon file gives us our exploit server json file so it excuted it.

<img width="1002" height="298" alt="image" src="https://github.com/user-attachments/assets/11e43772-1432-43c3-821a-7dec13be6209" />

Reload page change language to es and also generate alert and lab is solved

<img width="1772" height="582" alt="image" src="https://github.com/user-attachments/assets/a73ee244-b2c5-456c-9ea0-bd4bbdd71163" />

Lab is solved

<img width="1686" height="341" alt="image" src="https://github.com/user-attachments/assets/af6a00fa-f070-40fe-85ee-c488393f878f" />


---

### LAB 12 - Cache key injection

### Lab Description

<img width="841" height="662" alt="image" src="https://github.com/user-attachments/assets/cf7e388e-4812-4ce6-8f0c-21fd2f874028" />

### Solution

After starting lab we see login Page.

<img width="1256" height="460" alt="image" src="https://github.com/user-attachments/assets/77fb6212-3d62-4c25-a232-8f3c6f59b501" />

	Second Page of our lab /login
	
<img width="1377" height="256" alt="image" src="https://github.com/user-attachments/assets/a4996308-2345-4156-aa29-f54101bfe56b" />

Intercept the first Page through burp

<img width="1778" height="551" alt="image" src="https://github.com/user-attachments/assets/b79d8346-924a-460b-a205-2e4ce59b1dae" />

	
The when I click on `/myaccount` an intercept it through burp I see that Intercept  page is redirecting us to `/login`

<img width="1480" height="456" alt="image" src="https://github.com/user-attachments/assets/5af622f5-0167-449e-8788-b81edb13c27b" />

	
After redirecting we see the login page.


<img width="1823" height="532" alt="image" src="https://github.com/user-attachments/assets/c7f8c77a-31d3-42ca-bfc5-d5c00d2d71ed" />


Now adding  `&` will url encode it but `?` Doesnot encode and reflected in response


<img width="1768" height="579" alt="image" src="https://github.com/user-attachments/assets/6fda6d46-a600-456a-9cd5-4df86b5348a6" />

This allows you append arbitrary unkeyed content to the lang parameter:

 `/login?lang=en?utm_content=anythin`


<img width="1866" height="663" alt="image" src="https://github.com/user-attachments/assets/431e65dc-b922-47fd-b773-b8075323fb1e" />


	We can see  `/js/localize.js` file in the script tag
	And also0e `/js/localize.js?lang=en&cors=0` in re[ponse

<img width="1893" height="630" alt="image" src="https://github.com/user-attachments/assets/ded017af-dd16-4b9e-b411-57c4901b47f9" />


Observe that the page at `/login/` has an import from `/js/localize.js`. This is vulnerable to client-side parameter pollution via the lang parameter because it doesn't URL-encode the value.We can also see that cahe is dependent on **orgin** from response.

<img width="1175" height="439" alt="image" src="https://github.com/user-attachments/assets/45a16225-e29d-4cdd-8071-244c54877220" />

We will send this below request first because it will craft alert in the cahe which make alert then from second requet below we call  the origin to solved the lab 


<img width="1586" height="536" alt="image" src="https://github.com/user-attachments/assets/293f91e8-2250-4ab6-9d56-cacd06ba3af9" />

 ```
 GET /js/localize.js?lang=en?utm_content=z&cors=1&x=1 HTTP/1.1 Origin: x%0d%0aContent-Length:%208%0d%0a%0d%0aalert(1)$$$$
 ```

I am continously sending this request  below

  ```
	
 GET /login?lang=en?utm_content=x%26cors=1%26x=1$$origin=x%250d%250aContent-Length:%208%250d%250a%250d%250aalert(1)$$%23 HTTP/2

 ```
 
Calling the the origin in baopve payload which is saved in cache to solved the lab .The reson is it is not solving is our origin o is in small letter in our header request the lower case is comply with  with the HTTP/2 specification.


<img width="1901" height="544" alt="image" src="https://github.com/user-attachments/assets/f1fab9ac-98fd-4ee2-9365-3b3a40e7bb2b" />

	
	Now Make **O of Origin** in Capital letter and sending request will solved the lab
	
 <img width="1902" height="535" alt="image" src="https://github.com/user-attachments/assets/802c210c-524f-4007-bcdc-beaff1b4502a" />


<img width="1676" height="317" alt="image" src="https://github.com/user-attachments/assets/2662031a-fb6e-4d2d-a89d-df003e551622" />

---

### LAB 13 - Internal cache poisoning

### Lab Description

<img width="851" height="326" alt="image" src="https://github.com/user-attachments/assets/8dca1cde-659e-4f24-afb1-b74beb34f85a" />

### Solution

When we open lab we see a page with exploit server


<img width="1706" height="318" alt="image" src="https://github.com/user-attachments/assets/75902b07-f6ac-4cca-8850-22a965f9d3b7" />

	
Intercepting above request we can see that  our host is reflected in response.

 <img width="1893" height="820" alt="image" src="https://github.com/user-attachments/assets/57b02587-f2a6-4c55-a0db-f1d2fc30cb66" />

	Now use param miner in burp community to identify hidden headers


<img width="1903" height="508" alt="image" src="https://github.com/user-attachments/assets/61554f75-a35e-43d6-857d-47af2fa449a8" />



Below is default configuartion of  the param miner

<img width="1187" height="603" alt="image" src="https://github.com/user-attachments/assets/d9e1b9a0-2c12-446f-a69f-69030e91dadc" />


Pram miner doesnot identify any header

<img width="1373" height="315" alt="image" src="https://github.com/user-attachments/assets/641d4127-e3a4-4cf9-857b-504e2074bbaa" />


 Now again using param miner to scan header but this time we have also  Add dynamic cache buster option select.

<img width="567" height="83" alt="image" src="https://github.com/user-attachments/assets/9df6b73f-d450-43b0-9055-9a4463c38503" />


 
Now the above configuration identify that X-Forwarded-Host is allowed.

<img width="1422" height="372" alt="image" src="https://github.com/user-attachments/assets/2786f09c-9c6e-4bce-bbfc-3d45fbc27453" />


Now adding `X-Forwarded-Host` we can see that it has  overwritten the host
And we can see the file link to it are also link to our exploit server
File link to exploit server are :

```

/resources/js/analytics.js
/js/geolofcate.js?callback=loadCountry

```

<img width="1910" height="815" alt="image" src="https://github.com/user-attachments/assets/ae8e8332-15c5-4709-b900-ae1b8961f608" />


After sending above request we can see in our access log we have `404` request in ou exploit server from exploit server.

<img width="1887" height="529" alt="image" src="https://github.com/user-attachments/assets/4fd3d488-6e21-47aa-8f03-834d3cf9d237" />

We can see that load Country is directly coming form url.

<img width="1138" height="178" alt="image" src="https://github.com/user-attachments/assets/a4654d45-9cd2-4426-8b16-60283c9d5b6f" />

Changing load country to arbitary word is reflected in reponse,So it can be affected by xss.

<img width="1655" height="304" alt="image" src="https://github.com/user-attachments/assets/df03e537-f9af-4855-9d82-62b6b68a44ac" />


Loooking at `analytics.js` shows us that it is generating random id.

<img width="1064" height="265" alt="image" src="https://github.com/user-attachments/assets/d631f102-27dc-4790-b506-fec0c17a0fcd" />

Goes to the exploit server and create a file at `/js/geolocate.js` containing the payload `alert(document.cookie)`. Store the exploit.

<img width="1210" height="846" alt="image" src="https://github.com/user-attachments/assets/c8be8a0f-bac9-41c6-b751-78b67348b5e7" />


Now sending request with cache buster we can se it is reflected in reponse

<img width="1826" height="681" alt="image" src="https://github.com/user-attachments/assets/98208e48-eaf4-4fec-88c3-ea02334ea038" />


Back in Burp Repeater, disable the dynamic cache buster in the query string and re-add the `X-Forwarded-Host` header to point to your exploit server.

Send the request over and over until all three of the dynamic URLs in the response point to your exploit server. Keep replaying the request to keep the cache poisoned until the victim user visits the page and the lab is solved.

<img width="1905" height="725" alt="image" src="https://github.com/user-attachments/assets/0fc1174b-02c9-460b-ac6a-b6bc9448108f" />


After sending above request we can see **200** `gelocate.js` response because we are serving it on our exploit server


<img width="1894" height="216" alt="image" src="https://github.com/user-attachments/assets/86977831-7a18-4e7e-8a46-a750ac3fd822" />


And finally lab is solved


<img width="1460" height="289" alt="image" src="https://github.com/user-attachments/assets/8f0a0a9a-3e3c-4096-9cc2-747457248f8a" />


---
