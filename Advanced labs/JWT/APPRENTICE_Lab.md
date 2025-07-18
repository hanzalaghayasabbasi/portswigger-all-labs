## Labs Covered

This write-up focuses on the following labs from the PortSwigger Web Security Academy related to **JWT (JSON Web Token)** vulnerabilities:

**JWT authentication bypass via unverified signature**   
This lab demonstrates how attackers can bypass authentication by exploiting JWT implementations that fail to verify the token's signature.

**JWT authentication bypass via flawed signature verification** 
This lab shows how attackers can exploit incorrect signature verification logic to bypass authentication.


---

### LAB 1 - JWT authentication bypass via unverified signature

### Lab Description

<img width="867" height="558" alt="image" src="https://github.com/user-attachments/assets/2cda800f-8431-481f-ab54-7ef3aa9d37ab" />

### Solution

So we try to login as admin

<img width="1385" height="448" alt="image" src="https://github.com/user-attachments/assets/a9b8a420-a7e5-4323-9c0f-8da5b0212285" />


First we use extension which will tell us which is JSON requets,So as we can see in blue the json request login as wiener

<img width="1836" height="417" alt="image" src="https://github.com/user-attachments/assets/dd5d3770-c2a5-458c-a2e6-a7bf7806aeff" />



The we send myaccount request to repeater and the copy cookie

<img width="1787" height="738" alt="image" src="https://github.com/user-attachments/assets/156025f0-2339-4cc2-8cd1-85e302074574" />



So I paste thie request in `https://token.dev/`and see the result and we can manuplate the request in this tool

<img width="1625" height="621" alt="image" src="https://github.com/user-attachments/assets/cf0bb323-33ef-4da5-ba69-88efb32a8d2f" />


After manuplating the request we set sub to administrator copy the JWT string

<img width="1631" height="632" alt="image" src="https://github.com/user-attachments/assets/f076fa5d-09df-4efd-b618-1f66e7485b29" />


Then copy and paste the above jwt in the session and send to repeater and we can see the **admin panel**,And method to delete the wiener


<img width="1914" height="774" alt="image" src="https://github.com/user-attachments/assets/ef0663a7-a6c1-4b34-8d42-9be6be6abbfa" />


Copying and Pasting the method of deleting carlos we can see that the it giving us 302 reponse which means its deleting carlos  and then we follow rediretcion 
And open the session in burp then lab is solved



<img width="1228" height="651" alt="image" src="https://github.com/user-attachments/assets/7d3e270c-3abb-430f-bfce-eacf1a7b89f3" />

<img width="1898" height="632" alt="image" src="https://github.com/user-attachments/assets/fd03788d-0473-49e2-9cea-d28519bba360" />


---

### LAB 2 - JWT authentication bypass via flawed signature verification

### Lab Description

<img width="901" height="587" alt="image" src="https://github.com/user-attachments/assets/6cded08a-d20e-4845-9c6d-4deb995db539" />



###  Overview: Accepting Tokens with No Signature (JWT `alg=none` Vulnerability) 

**What is it?**
A critical JWT vulnerability arises when a server accepts tokens with **no cryptographic signature**, typically when the token's header contains:

```json
{ "alg": "none" }
```

This indicates an **"unsecured JWT"**, meaning the token is not signed at all — it’s just base64-encoded data that anyone can forge.

---

###  Why It's Dangerous 

The core flaw lies in **trusting unverified, user-supplied input**. The `alg` field tells the server what algorithm to use to verify the token, but this instruction itself is part of the untrusted token.

* The server *hasn't yet validated the token*, so blindly accepting `alg: none` gives the attacker full control over the verification process.
* This can allow an attacker to **forge arbitrary tokens** by:

  * Setting `alg` to `none`
  * Omitting the signature
  * Supplying a fake payload (e.g., escalating privileges to `admin`)

---

### Example Attack 

1. **Original JWT:**

   ```
   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QifQ.SIGNATURE
   ```

2. **Attacker-modified token:**

   ```
   eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.
   ```

   * `alg` is set to `none`
   * No signature is included
   * The server, if misconfigured, will accept it and treat the user as `admin`

---

###  Bypass Techniques 

Even if the server appears to reject `alg=none`, filters may be bypassed using:

* Mixed capitalization: `NoNe`, `NONE`
* Unicode/hex/URL encodings
* Tampered headers in base64 (e.g., extra padding or malformed characters)

---
### Solution


First we will try to access admin panel but it is giving us  admin interface is available administrator


<img width="1385" height="448" alt="image" src="https://github.com/user-attachments/assets/7de2ac30-890c-4fcd-b3bd-8bccc10ec9ea" />


So Iogin as wiener and intercept at  back  we can see at blue sign which is  telling us its valid using extension of burp

<img width="1870" height="673" alt="image" src="https://github.com/user-attachments/assets/5cdb8102-58e8-4861-abab-0ff6e31b0981" />


As we can see that decoded jwt

<img width="1638" height="615" alt="image" src="https://github.com/user-attachments/assets/90a09a09-36e4-478d-b67e-62a2da428a6b" />


Now I change wiener to administrator and copy it


<img width="1649" height="643" alt="image" src="https://github.com/user-attachments/assets/d6c3221a-1f45-4c42-9fe5-876389ad038e" />



Then I paste the jwt and change id to administrator and paste above jwt token and send requets

<img width="1444" height="697" alt="image" src="https://github.com/user-attachments/assets/0e9c7658-2a7e-42a0-86eb-ce9d340e452d" />


After Sending request we can see that I logout 
It could be that it doesn’t valid what algorithm is being used so we can try to set `alg` to `none`

<img width="1319" height="727" alt="image" src="https://github.com/user-attachments/assets/0f59dec8-8dbf-4c10-a34d-95e1bc8d905d" />


Or we can also try to login as admin but  jwt token is not working


<img width="1735" height="777" alt="image" src="https://github.com/user-attachments/assets/aa3995e4-6380-4c9a-988b-ffb4f54b17b8" />






It could be that it doesn’t valid what algorithm is being used so we can try to set `alg` to `none`
But also to add . at the end of payload part

Even if the token is unsigned, the payload part must still be terminated with a trailing dot.


<img width="1223" height="368" alt="image" src="https://github.com/user-attachments/assets/4aff14ad-152c-40c2-9348-3e530bbfad70" />


As we can see that after setting algo to 0 and adding tarling charcter . We can login as admin
 
		
<img width="1649" height="728" alt="image" src="https://github.com/user-attachments/assets/2e6ea56f-fd42-48df-9445-67c9bbf1bbfe" />



And after open request in browser we can delete user and then lab is solved


<img width="1702" height="628" alt="image" src="https://github.com/user-attachments/assets/f8b01eac-6aef-4c3a-93ef-f403ab1ac046" />




---

