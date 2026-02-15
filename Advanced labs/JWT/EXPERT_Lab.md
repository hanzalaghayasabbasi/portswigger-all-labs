## Labs Covered

This write-up focuses on the following **EXPERT-level labs** from the PortSwigger Web Security Academy related to **JWT (JSON Web Token)** vulnerabilities:

**7 JWT authentication bypass via algorithm confusion**  
This lab demonstrates how attackers can bypass authentication by exploiting algorithm confusion vulnerabilities in JWT implementations.

**8 JWT authentication bypass via algorithm confusion with no exposed key**  
This lab shows how attackers can exploit algorithm confusion even when no public signing key is exposed.

---

### LAB 7 - JWT authentication bypass via algorithm confusion

### Lab Description

<img width="885" height="771" alt="image" src="https://github.com/user-attachments/assets/48539a89-e69b-4547-8124-72b2d01d1ce7" />



### Overview: JWT Algorithm Confusion (Key Confusion Attack)

**What is it?**
JWT algorithm confusion is a critical vulnerability where a server accepts a token signed with a different algorithm than intended. An attacker can exploit this by switching the `alg` field in the JWT header to trick the server into verifying a forged token.

---

### Why It's Dangerous

JWT supports both:

* **Symmetric algorithms** (e.g., HS256): Same key is used for signing and verification.
* **Asymmetric algorithms** (e.g., RS256): Private key is used to sign, public key is used to verify.

If a server expects RS256 but an attacker sends a JWT with `alg: HS256`, some poorly configured libraries may accept it and use the **public key as the HMAC secret**, effectively allowing attackers to forge valid tokens.

---

### How the Exploit Works

**Step 1: Obtain the Public Key**
Public keys are often exposed via:

```
/.well-known/jwks.json
```

or may be extracted from existing tokens. These keys are typically in JWK format.

Example JWK:

```json
{
  "kty": "RSA",
  "e": "AQAB",
  "n": "o-yy1wpYmf...",
  "kid": "75d0ef47..."
}
```

**Step 2: Convert Public Key to a Secret**
Convert the JWK to PEM format, then Base64-encode it. This becomes the secret used in HMAC signing.

Tools like Burp Suite JWT Editor can perform this conversion easily.

**Step 3: Craft a Malicious JWT**
Create a JWT with:

* `alg` set to `HS256`
* A payload of your choice (e.g., `{"role": "admin"}`)
* Sign the token using the Base64-encoded public key as the HMAC secret

**Step 4: Send the Token to the Server**
If the server incorrectly uses the public key as an HMAC secret, it will accept the token as valid, giving the attacker unauthorized access.

---

### Example Attack Flow

1. Change JWT header:

   ```json
   { "alg": "HS256", "typ": "JWT" }
   ```
2. Use a payload like:

   ```json
   { "user": "admin" }
   ```
3. Sign the JWT using HMAC-SHA256 with the public key as the secret
4. Submit the token to the server

If the server is vulnerable, it accepts the token and treats the attacker as an authenticated or privileged user.

---

### Solution

As we  can see that admin panel is  accessible to administrator only.


<img width="1883" height="407" alt="image" src="https://github.com/user-attachments/assets/ff14b24f-5121-4627-90b0-c4fd770fbc34" />



In the browser, go to the standard endpoint **/jwks.json** and observe that the server exposes a JWK Set containing a single public key.


<img width="1862" height="179" alt="image" src="https://github.com/user-attachments/assets/04fbf99e-0c86-4268-ae45-daa8135a85e8" />



Now we want public to sign our jwt token ,Now the public key is not in correct form to sign, So we  create New Rsa key  and paste the same public key as above in jwks.json and first paste  above public key start from KTY  and it was obsufcate, Now press jwk and it remove obsufaction

<img width="1909" height="716" alt="image" src="https://github.com/user-attachments/assets/6444f664-cc55-490e-8673-1d95155080a7" />


Then we will Public key as pem as shown below( PEM (Privacy Enhanced Mail) format is often used for verifying the signature of the JWT).


<img width="1917" height="483" alt="image" src="https://github.com/user-attachments/assets/b8c774d8-9c97-4de5-8586-a93489f26787" />


Encode PEM key from decoder

<img width="1910" height="520" alt="image" src="https://github.com/user-attachments/assets/3d0b69ac-58f4-4eef-aece-fc7ddf426fe9" />

Then we will generate New Symmetric key and click on generate and paste Encoded above pem public key in k and then used tis signature
Of jwt

<img width="1911" height="693" alt="image" src="https://github.com/user-attachments/assets/7d41e6d6-c1d4-450b-93eb-9f9ea922b6f3" />


Second One is secret key which we will used for signing

<img width="1910" height="362" alt="image" src="https://github.com/user-attachments/assets/32ee2086-dc89-4f3b-8964-4c11ab8e1a68" />


Change alg to **HS256** FROM **RS256** and change sub to administrator

<img width="1706" height="791" alt="image" src="https://github.com/user-attachments/assets/40238fef-e21f-49c7-b3dd-297403af87a7" />

 Now try to access admin and we will get the admin

<img width="1644" height="720" alt="image" src="https://github.com/user-attachments/assets/374b0eff-eac5-4306-99f5-8e0656c3797c" />


Now deleted carlos user to solve the lab

<img width="1332" height="552" alt="image" src="https://github.com/user-attachments/assets/ec4a21a5-5a49-4a70-99fe-a520259a1cdf" />

 After deleting carlos and follow redirection lab is solved


<img width="1909" height="731" alt="image" src="https://github.com/user-attachments/assets/ec635d8c-af67-4054-b420-f2439a232627" />


In cases where the public key isn't readily available, you may still be able to test for algorithm confusion by deriving the key 
from a pair of existing JWTs. This process is relatively simple using tools such as jwt_forgery.py. You can find this, along with several other useful scripts, on the rsa_sign2n GitHub repository.
We have also created a simplified version of this tool, which you can run as a single command:
docker run --rm -it portswigger/sig2n <token1> <token2>

**Note**
You need the Docker CLI to run either version of the tool. The first time you run this command, it will automatically pull the image from Docker Hub, which may take a few minutes.



---

### LAB 8 - JWT authentication bypass via algorithm confusion with no exposed key

### Lab Description

<img width="873" height="784" alt="image" src="https://github.com/user-attachments/assets/5965a61d-d917-481f-a89e-2d0e9c967f26" />

### Solution

Login as wiener

<img width="1820" height="501" alt="image" src="https://github.com/user-attachments/assets/d291a9c1-86a3-4548-83a5-c94105a1ba90" />

<img width="1817" height="236" alt="image" src="https://github.com/user-attachments/assets/625fdfb5-fd8a-45c2-9c8e-315ae52713b1" />

In the cookie we have jwt key

<img width="1920" height="559" alt="image" src="https://github.com/user-attachments/assets/1de28ca8-6bfe-4b95-bfd4-b8ec195d4dbe" />

Copy your JWT session cookie and save it somewhere for later.

Log out and log in again.

Copy the new JWT session cookie and save this as well. You now have two valid JWTs generated by the server

<img width="1875" height="587" alt="image" src="https://github.com/user-attachments/assets/f2b1e2a4-22c9-4320-ab64-22dad0151483" />

### Brute-force the server's public key

In a terminal, run the following command, passing in the two JWTs as arguments.
```
docker run --rm -it portswigger/sig2n <token1> <token2>
```
**Note** that the first time you run this, it may take several minutes while the image is pulled from Docker Hub.

<img width="1883" height="645" alt="image" src="https://github.com/user-attachments/assets/9aaac565-8725-4606-af8e-458bd88514fa" />

Notice that the output contains one or more calculated values of n. Each of these is mathematically possible, but only one of them matches the value used by the server. In each case, the output also provides the following:

A Base64-encoded public key in both X.509 and PKCS1 format.

A tampered JWT signed with each of these keys.

Copy the tampered JWT from the first X.509 entry (you may only have one).


<img width="1901" height="776" alt="image" src="https://github.com/user-attachments/assets/5ac31b69-b8be-4566-af65-6ed80ee3f79d" />


<img width="1543" height="625" alt="image" src="https://github.com/user-attachments/assets/9fb82fa9-3d0a-44f7-b9d3-b6dc4afbdf94" />

Go back to your request in Burp Repeater and change the path back to /my-account.

Replace the session cookie with this new JWT and then send the request.


If you receive a 200 response and successfully access your account page, then this is the correct X.509 key.

<img width="1543" height="625" alt="image" src="https://github.com/user-attachments/assets/eb53c9de-ada0-4239-8dde-84979a1fef95" />


<img width="1879" height="647" alt="image" src="https://github.com/user-attachments/assets/7b7f37a2-6e4a-45fe-abc2-e98c3dab3abe" />


If you receive a 302 response that redirects you to /login and strips your session cookie, then this was the wrong X.509 key. In this case, repeat this step using the tampered JWT for each X.509 key that was output by the script.

<img width="1879" height="647" alt="image" src="https://github.com/user-attachments/assets/5d4c3292-425a-4aad-a010-defa7f4fcf2c" />

<img width="1567" height="704" alt="image" src="https://github.com/user-attachments/assets/9034647a-b601-4ddd-b141-5b9c750125d5" />

redirect to 302

<img width="947" height="294" alt="image" src="https://github.com/user-attachments/assets/9cd3e7b6-556e-410b-aca6-f395237b1433" />



### Generate a malicious signing key

From your terminal window, copy the Base64-encoded X.509 key that you identified as being correct in the previous section. Note that you need to select the key, not the tampered JWT that you used in the previous section.

<img width="1905" height="642" alt="image" src="https://github.com/user-attachments/assets/60accb55-f7d0-42c6-9e0d-b3ccedf9ac43" />

In Burp, go to the JWT Editor Keys tab and click New Symmetric Key.

In the dialog, click Generate to generate a new key in JWK format.

Replace the generated value for the k property with a Base64-encoded key that you just copied. Note that this should be the actual key, not the tampered JWT that you used in the previous section.
<img width="1920" height="713" alt="image" src="https://github.com/user-attachments/assets/e009dae7-bb9b-4d89-848a-6c8b23d69a5c" />

Save the key.

<img width="1751" height="689" alt="image" src="https://github.com/user-attachments/assets/fbc6bd53-32fa-4bd0-b2c1-73b5688301e3" />

#### 1. **Go to the Burp Repeater tab**

* Locate the request to `/admin` in Burp Repeater.
* Change the **request path** from its original endpoint (e.g. `/my-account`) to:

```
/admin
```

#### 2. **Open the JWT in the extension tab**

* Switch to the **"JSON Web Token"** tab (if using the JWT Editor extension).
* You should see the JWT split into Header, Payload, and Signature.

---

#### 3. **Modify the JWT**

* **Header**: Make sure this looks like:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

* **Payload**: Change the `sub` (subject) field to `administrator`. For example:

```json
{
  "sub": "administrator",
  "iat": <keep_original_value>,
  ...
}
```

(Keep other fields unchanged unless instructed.)

---

#### 4. **Sign the token**

* At the **bottom of the JWT tab**, click **Sign**.
* Choose **HS256** and **select the symmetric key** you found earlier (likely the server's public key, used as the HMAC key).
* Make sure **“Don't modify header”** is selected so the alg remains HS256.
* Click **OK** — the JWT is now signed properly.

---

#### 5. **Send the modified request**

* The Authorization header (or Cookie) should now contain the updated JWT.
* Click **Send**.
* You should now get access to the **admin panel**.

---

#### 6. **Delete Carlos**

* In the response, search for:

```
/admin/delete?username=carlos
```

* Copy this URL, and send a **new GET request** to that endpoint in Burp Repeater.

---

**Lab should now be solved**, and you will see a success message.

<img width="1660" height="808" alt="image" src="https://github.com/user-attachments/assets/559fbf34-59ae-42c6-885a-abf0694facbe" />



---

