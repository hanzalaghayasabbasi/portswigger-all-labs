## Labs Covered

This write-up focuses on the following **PRACTITIONER-level labs** from the PortSwigger Web Security Academy related to **JWT (JSON Web Token)** vulnerabilities:

**JWT authentication bypass via weak signing key**
This lab demonstrates how a weak or guessable signing key allows attackers to forge valid JWTs and bypass authentication.

**JWT authentication bypass via jwk header injection**  
This lab demonstrates how attackers can inject a malicious JWK (JSON Web Key) into the JWT header to forge a valid token and bypass authentication.

**JWT authentication bypass via jku header injection**  
This lab shows how attackers can manipulate the `jku` header to point to an attacker-controlled key set, allowing them to sign forged tokens.

**JWT authentication bypass via kid header path traversal**  
This lab demonstrates how attackers can exploit insecure file path resolution in the `kid` header to retrieve secret keys and forge tokens.

---

### LAB 3 - JWT authentication bypass via weak signing key

### Lab Description

<img width="870" height="626" alt="image" src="https://github.com/user-attachments/assets/541c445c-4d89-4d66-bfca-bae6faed1c21" />


### Brute-Forcing JWT Secret Keys (`HS256`) 

**What’s the issue?**
JWTs signed using symmetric algorithms like `HS256` rely on a **shared secret key**. If this key is weak, predictable, or hardcoded (e.g., `"secret"`, `"password"`, or `"123456"`), an attacker can **brute-force the key** and **forge valid tokens** with arbitrary payloads — including admin access.

---

### How It Happens

Developers sometimes:

* Use weak, default, or demo secrets (like `"secret"`).
* Copy code from tutorials and forget to change the example key.
* Hardcode credentials in source code repositories.

If an attacker gets hold of a signed JWT (via a session, HTTP traffic, logs, etc.), and the server uses `HS256`, the attacker can:

1. Extract the **header and payload**.
2. Brute-force the **secret key** offline.
3. Resign a forged JWT with arbitrary claims.

---

###  Using `hashcat` to Crack JWT Secrets 

> Requires: Kali Linux (or install `hashcat`), a valid JWT, and a wordlist (e.g., `rockyou.txt`) 

**Step 1:** Save your JWT to a file (e.g., `token.jwt`)
**Step 2:** Run the following command:

```bash
hashcat -a 0 -m 16500 token.jwt /usr/share/wordlists/rockyou.txt
```

**Explanation:**

| Option        | Description                          |
| ------------- | ------------------------------------ |
| `-a 0`        | Dictionary attack (straight mode)    |
| `-m 16500`    | Hash mode for JWT (HMAC-SHA256)      |
| `token.jwt`   | File containing the JWT to crack     |
| `rockyou.txt` | Wordlist to try as potential secrets |

**Step 3:** If successful, Hashcat will output the **correct secret key**.

---

### Example Output 

```
JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
FOUND: secret = 'supersecret123'
```

---

### Exploit Path After Cracking

Once you know the key:

1. Modify the JWT payload (e.g., change `"role": "user"` → `"role": "admin"`).
2. Resign the token using the cracked secret.
3. Use the modified JWT to bypass authentication or escalate privileges.

    Tools to resign JWTs: 

* **Burp Suite's** *JWT Editor* extension
* **[jwt.io](https://jwt.io/)** debugger
* Custom scripts in Python (using `PyJWT`)

---




### Solution


In this lab js token has weak signature applied.So we can brute force it

So I intercept blue highlight which tell us it is jwt and copy and paste in token.dev  as it tell us wiener authetication

<img width="1585" height="740" alt="image" src="https://github.com/user-attachments/assets/8f9a3c5f-3d87-471f-9738-816a777fd766" />


change sub to adminsitrator

<img width="1555" height="677" alt="image" src="https://github.com/user-attachments/assets/43a7cc70-7a65-412b-969a-ed0b6e7d13c6" />


The I try to access adminisntaor with above jwt token but I did not get any result

<img width="1420" height="715" alt="image" src="https://github.com/user-attachments/assets/fbd5dda0-16f2-4e41-9f12-4845dba218c4" />


Use another method to access admin but no result

<img width="1401" height="633" alt="image" src="https://github.com/user-attachments/assets/d4f86eea-f4c7-4a4a-9a69-94b3d9945b42" />


So Save the jwt token on file and brute force it with  with seclist jwt token wordlist we get sign word which which
Is used to sign jwt token

<img width="1254" height="618" alt="image" src="https://github.com/user-attachments/assets/ab6894e9-e989-4cfc-9044-e4ed879accdf" />


Chang jwt to  adminsitrator and sign it with secret1 key and press go

<img width="1005" height="720" alt="image" src="https://github.com/user-attachments/assets/825d353a-5d50-41c2-958a-4dda1bd6e09f" />


As we can see additional paramter is insert The following….. So it gives us abd request

<img width="1410" height="596" alt="image" src="https://github.com/user-attachments/assets/9c09b892-3d61-4be0-b275-191fcdf598d1" />


Remove additional header and now we can Access admin

<img width="1633" height="628" alt="image" src="https://github.com/user-attachments/assets/cc5d2da2-0e9d-4f71-b0c3-7f74bd4f4ea5" />

Delete user carlos and lab is solved

<img width="1214" height="615" alt="image" src="https://github.com/user-attachments/assets/6c9bb145-ffa1-4b8c-b3e6-6ef8ee96a2e0" />



---

### LAB 4 - JWT authentication bypass via jwk header injection

### Lab Description

<img width="875" height="565" alt="image" src="https://github.com/user-attachments/assets/2625fafa-747a-4b52-a2e2-75dde5da530b" />


###  JWT Header Parameter Injections – Overview 

**What is it?**
JWT header parameter injection occurs when a server **blindly trusts JWT header fields** such as `jwk`, `jku`, or `kid` to determine **which key to use** for signature verification. If improperly validated, this can allow an attacker to **bypass authentication** by supplying their own keys.

---

###  Key JWT Header Fields Vulnerable to Abuse 

| Header | Description                                                                              |
| ------ | ---------------------------------------------------------------------------------------- |
| `alg`  | Algorithm used to sign the JWT (e.g., `HS256`, `RS256`) — already well-known for misuse. |
| `jwk`  | **JSON Web Key** — allows the client to embed a public key directly in the header.       |
| `jku`  | **JSON Web Key Set URL** — tells the server where to fetch public keys (remotely).       |
| `kid`  | **Key ID** — used to select a key from a set of public keys based on an identifier.      |

---

### Exploiting `jwk`: Injecting Self-Signed JWTs

1. **Attacker creates their own RSA key pair.**
2. They generate a **valid JWT** with arbitrary claims (e.g., `admin: true`).
3. They **sign it with their private key**.
4. They place the matching **public key** in the JWT header's `jwk` field.

####  Example JWT Header with JWK:

```json
{
  "alg": "RS256",
  "jwk": {
    "kty": "RSA",
    "n": "base64url-modulus",
    "e": "AQAB"
  }
}
```

5. If the server **uses the embedded key for verification**, it will accept the forged token.

---

###  Real-World Risk

* Complete **authentication bypass** if server verifies JWTs using arbitrary keys from headers.
* **Privilege escalation** if roles/permissions are encoded in JWT payloads.

---

### 🧰 Tools

*  [Burp Suite's JWT Editor](https://portswigger.net/burp) supports adding/modifying `jwk` headers and re-signing tokens.
*  `jwt_tool.py` can help craft and test custom headers and signature manipulations.

---

### Solution

As we know from descrption that  The server supports the **jwk** parameter in the **JWT** header. This is sometimes used to embed the correct verification key directly in the token. However, it fails to check whether the provided key came from a trusted source.login as wiener and peter
While intercepting request at back where blue sign come we will intercept it

<img width="1497" height="782" alt="image" src="https://github.com/user-attachments/assets/be93b555-0850-40f5-8cd8-30d6c1ff1d7b" />


Now I try to login as adminstarator directly  **302** found,I open the request in browser and see that we  are logout of our account

<img width="1326" height="693" alt="image" src="https://github.com/user-attachments/assets/818d385a-c239-4641-9b91-78b27d31e2af" />


Now I try to access admin but Unauthorized message came up

<img width="1240" height="440" alt="image" src="https://github.com/user-attachments/assets/4ba199cc-e379-47f9-8a76-c766d395dae6" />


Now using jwt  editor genarartor  to get rsa key,We can see that RSA key is genrated but we donot specify any size it automatically select size
Since I did not have the private key to sign my forged token, I decided to create my own key pair using the JWT Editor extension and use that key pair for signing my JWT and somehow enforce the server to verify the token using my public key.

<img width="1479" height="857" alt="image" src="https://github.com/user-attachments/assets/4c824a47-5472-416e-b6b0-b1619bdf51c6" />


After pressing ok this tab below will come


<img width="1903" height="450" alt="image" src="https://github.com/user-attachments/assets/7c752ecf-dbb0-4388-bd9b-b588f8d50760" />


Now we have genrated RSA , now it time to select it we can select it through JSON WEB TOKEN , So I clicked on attack and the embedded JWK
According to the lab title, some header injection was possible in the token. I decoded the header, and the signing key was using the **RS256** algorithm unlike the previous lab. This meant that there was no shared key and the server was using an RSA key pair for signing and verifying the JWTs.
Private key is used to sign the token and public key is used to verify the token.

<img width="1543" height="912" alt="image" src="https://github.com/user-attachments/assets/11f6f81d-9c7a-4ecd-b199-25c6d9df3532" />



And we can see select the same rsa key that we have generated in other tab

<img width="1292" height="699" alt="image" src="https://github.com/user-attachments/assets/333fad38-ec5b-4754-a4bb-d4a8a97e9c6d" />


One mistake I have done is that I doesnot change it to adminsiator So First change sub and
Then repeat above step of embedded jwk,after repeating above step we can see that jwk header is added

<img width="1277" height="601" alt="image" src="https://github.com/user-attachments/assets/9dfc9989-6f1c-4dfa-8dbb-5629c9bf080a" />



Now the jwk header is added we click on send and we can see that admin panel came

<img width="1478" height="825" alt="image" src="https://github.com/user-attachments/assets/8dacddd6-471b-4582-b558-8a4fbf297c4d" />


Now delete carlos to solve  the lab


<img width="1431" height="725" alt="image" src="https://github.com/user-attachments/assets/83d31aa7-ddae-4358-b0f3-332cc408c444" />



---

### LAB 5 - JWT authentication bypass via jku header injection

### Lab Description

<img width="869" height="581" alt="image" src="https://github.com/user-attachments/assets/e18b9d1f-d02c-4510-9b19-efe1acaed880" />

###  Overview: Injecting Self-Signed JWTs via the `jku` Header Parameter

**What is it?**
This vulnerability occurs when a server **trusts and fetches public keys** from a user-specified `jku` (JSON Web Key Set URL) in the JWT header to verify the token's signature.

Attackers can exploit this by hosting their own **JWK Set**, signing a forged JWT using their private key, and directing the server to fetch the public key from a malicious `jku` URL. If the server doesn’t validate the source properly, the forged token is accepted — enabling **authentication bypass**.

---

###  How It Works

1. **Generate RSA Key Pair**

   * Attacker creates their own private/public RSA keys.

2. **Host a Malicious JWK Set**

   * The attacker sets up a JWK Set containing the public key on a server they control (e.g., `https://evil.com/jwks.json`).

   ```json
   {
     "keys": [
       {
         "kty": "RSA",
         "kid": "attacker-key",
         "n": "<modulus>",
         "e": "AQAB"
       }
     ]
   }
   ```

3. **Craft a Malicious JWT**

   * Header:

     ```json
     {
       "alg": "RS256",
       "jku": "https://evil.com/jwks.json",
       "kid": "attacker-key"
     }
     ```
   * Payload:

     ```json
     {
       "user": "admin"
     }
     ```
   * Signature: Signed using the attacker’s private key.

4. **Send the JWT to the server**

   * If the server is vulnerable, it will:

     * Fetch the key from the `jku` URL.
     * Use the attacker's public key to verify the forged token.
     * Accept the token and grant unauthorized access.

---

###  What Is a JWK Set?

A **JWK Set** is a JSON object containing an array of **JWKs** (JSON Web Keys):

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "example-key-id",
      "n": "base64url-modulus",
      "e": "AQAB"
    }
  ]
}
```

Servers often expose these at:

```
/.well-known/jwks.json
```

---

###  Why It’s Dangerous

* The `jku` value is **user-controlled**.
* It tells the server where to get the **verification key**.
* If the server **doesn’t validate or restrict** this URL:

  * The attacker supplies their own key source.
  * The server trusts and verifies a **forged token**.

---

###  Attack Surface Expansion

If the server restricts key-fetching to trusted domains:

* Attackers may try **bypasses** like:

  * URL obfuscation (e.g., `https://trusted.com@evil.com`)
  * Open redirects on trusted hosts
  * DNS rebinding or SSRF via host headers

---


### Solution

`jku` provides a URL from which servers can fetch a set of keys containing the correct key.

First we can see that its wiener  account

<img width="1559" height="430" alt="image" src="https://github.com/user-attachments/assets/4d40bc33-472d-414f-8f84-c97b7529dd00" />


Now after looking at json web Token we can see algo and `sub=wiener`

<img width="1540" height="724" alt="image" src="https://github.com/user-attachments/assets/f246c942-d454-4123-90a9-33747838abcb" />


So we can see the content of RSA KEY.

<img width="1851" height="832" alt="image" src="https://github.com/user-attachments/assets/ee9449a4-9c46-403c-96b0-c1f9baf79e84" />

Now we copy public key from above made `rsa` key


<img width="1261" height="363" alt="image" src="https://github.com/user-attachments/assets/a8c7cace-e7ed-461f-8683-86396dbc74cd" />



Format of `jku` to store on sever

<img width="1188" height="395" alt="image" src="https://github.com/user-attachments/assets/04992176-0adf-43f3-93c4-2e1c778d2760" />



So we  paste the rsa public key on exploit sever as shown below just we add keys parameter synatx remaing are the copy form rsa from rsa

**file name : /.well-known/jwks.json(you can also give any_name in this case**


<img width="1651" height="817" alt="image" src="https://github.com/user-attachments/assets/69ca4cd3-d88a-4766-b8a6-ff7b71559bb1" />


Now navigate to exploit to look at it its working


<img width="1620" height="192" alt="image" src="https://github.com/user-attachments/assets/9e5f892c-600e-45a8-b1b8-46c224dac2f1" />



Now sign with key(I think private) because public is in exploit sever and **add administarator in sub** and **jku:url** added as shown below 

<img width="1724" height="890" alt="image" src="https://github.com/user-attachments/assets/bdf84c7f-2f5a-417c-8c93-f186d9a1a0fd" />


Or we can do above task  as this way choosing 3 option


<img width="1521" height="850" alt="image" src="https://github.com/user-attachments/assets/f59fc060-4e5a-40ea-b3c0-9130cda9fd07" />


Then we clcik on go and we get admin now delete carlos and lab  will be solved

<img width="1432" height="819" alt="image" src="https://github.com/user-attachments/assets/20f9d9eb-3fb8-4bfe-aa71-a8ab28f49973" />

---

### LAB 6 - JWT authentication bypass via kid header path traversal

### Lab Description

<img width="852" height="564" alt="image" src="https://github.com/user-attachments/assets/f2de68b0-326e-4d7b-abc7-deeb3685dbf5" />


###  Overview: Injecting Self-Signed JWTs via the `kid` Parameter

**What is it?**
The `kid` (Key ID) JWT header parameter helps the server decide **which key** to use when verifying the token’s signature. This seems benign — but when developers fail to sanitize or control this input, attackers can abuse `kid` to:

* Reference unintended files or data as keys
* Bypass verification using **empty strings or public files**
* Even launch **SQL injection attacks** when keys are retrieved from databases

---

###  Why It’s Dangerous

1. **`kid` is attacker-controlled**, but is blindly used to locate a verification key.
2. The `kid` value might reference:

   * A **file path** (e.g., `/dev/null`, `keys/admin.key`)
   * A **database entry** (e.g., `' OR 1=1 --`)
   * A **JWK ID** in a JWK Set
3. If the server supports **symmetric signing algorithms** like `HS256`, the attacker can forge valid tokens **if they guess or control the secret key**.

---

### Example Exploit Scenarios

#### 1.  **Directory Traversal (`kid` → file path)**

If the server uses something like this:

```python
with open("keys/" + kid + ".key", "r") as key_file:
```

An attacker can submit:

```json
{ "kid": "../../../../../dev/null" }
```

Then sign the token using an **empty secret string**, which matches the contents of `/dev/null`.

#### 2. **SQL Injection in `kid`**

If the server looks up keys from a database:

```sql
SELECT secret FROM jwt_keys WHERE kid = '$kid'
```

Then injecting:

```json
{ "kid": "' OR '1'='1" }
```

Could return the wrong key or **bypass filtering**.

---

###  Other Header Parameters of Interest

| Parameter                       | Risk / Use Case                                                                                                                                                                                                                                                                        |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `cty` (Content Type)            | Used to define the type of payload (e.g., `text/xml`, `application/x-java-serialized-object`). If signature checks are bypassed, can be used to trigger **XXE** or **Java deserialization** attacks.                                                                                   |
| `x5c` (X.509 Certificate Chain) | May allow injection of **self-signed certificates** if not validated properly. Parsing flaws in certificate chains have led to critical bugs (e.g., [CVE-2017-2800](https://nvd.nist.gov/vuln/detail/CVE-2017-2800), [CVE-2018-2633](https://nvd.nist.gov/vuln/detail/CVE-2018-2633)). |

---




### Solution


Access the admin Panel directly it is giving us administrator can access it.So we have to bypass it

<img width="1361" height="459" alt="image" src="https://github.com/user-attachments/assets/3d497910-79d0-4130-8f97-11d18a355f83" />


Now Intercept the request when I login as **wiener:peter** and send `myaccount?id=wiener` to repeater

<img width="1418" height="710" alt="image" src="https://github.com/user-attachments/assets/2a51cdd6-cfa8-49e4-aa4b-996782416318" />


As we can below decoded *jwt*  we can see that `hs256` which is symmetric key

<img width="1549" height="595" alt="image" src="https://github.com/user-attachments/assets/280e3521-0ce1-48e8-9b12-5569cd6d8901" />


Now will generate New symmetric key

<img width="1904" height="666" alt="image" src="https://github.com/user-attachments/assets/0fbd6845-9d9d-4633-973c-49ab5fbe559b" />


click **Generate** to generate a new key in JWK format. Note that you don’t need to select a key size as this will automatically be updated later.

<img width="1895" height="670" alt="image" src="https://github.com/user-attachments/assets/55151182-34eb-4a4c-97a2-47afbec10d6f" />


 <img width="707" height="141" alt="image" src="https://github.com/user-attachments/assets/a89aa7c2-a2c0-4ca2-8a67-3dcc4df2d3d3" />



Replace the generated value for the k property with a Base64-encoded null byte (AA==). Note that this is just a workaround because the JWT Editor extension won't allow you to sign tokens using an empty string.


<img width="1715" height="691" alt="image" src="https://github.com/user-attachments/assets/b58127bb-f5b1-413b-818e-b5148b539c97" />


• For symmetric encryption (where the same key is used for both encryption and decryption), "k" would typically contain the secret key encoded in Base64.
• For asymmetric encryption (where a pair of public and private keys are used), "k" would usually represent either the public key or the private key, depending on the context.


After changing the k to null we can see that that Public key is removed


<img width="1912" height="254" alt="image" src="https://github.com/user-attachments/assets/93b3699a-9fc8-47dc-88ce-3d0e0a2e94a7" />

• In the header of the JWT, change the value of the kid parameter to a path traversal sequence pointing to the `/dev/null` 
• `file:../../../../../../../dev/null`     and changing sub to administrator

<img width="1859" height="709" alt="image" src="https://github.com/user-attachments/assets/8a6db7cf-101c-48cc-996d-f4d453488429" />

At the bottom of the tab, click **Sign**, then select the symmetric key that you generated in the previous section.
Make sure that the **Don’t modify header** option is selected, then click **OK**. The modified token is now signed using a null byte as the secret key.


<img width="1455" height="712" alt="image" src="https://github.com/user-attachments/assets/5b0bddf9-fa54-47cb-bac4-d6a8ee0214e4" />


Now access the admin panel by sign and hangin jwt and now we can access the admin panel

<img width="1372" height="648" alt="image" src="https://github.com/user-attachments/assets/8308592f-dd18-41e8-a338-33ebafb40fae" />

Now we are deleting Carlos to solve the lab

<img width="1430" height="538" alt="image" src="https://github.com/user-attachments/assets/8cb111d8-98a6-4e71-b4ee-b44a7f292532" />


---
