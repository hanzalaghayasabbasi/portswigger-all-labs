# Lab Covered

This write-up focuses on the following **EXPERT-level** labs from the PortSwigger Web Security Academy:

---

### **Broken brute-force protection, multiple credentials per request**

This lab demonstrates how a flawed authentication mechanism allows multiple credential pairs to be submitted within a single HTTP request. The server processes each set independently, which enables attackers to bypass standard rate-limiting controls and perform large-scale brute-force attacks efficiently. The lab emphasizes the importance of validating and strictly controlling request formats during authentication.

---

### **2FA bypass using a brute-force attack**

This lab demonstrates how insufficient brute-force protection on the second authentication factor (2FA) allows attackers to systematically guess 2FA codes once valid primary credentials have been compromised. The absence of proper rate-limiting or account lockout mechanisms on the 2FA step renders multi-factor authentication ineffective. The lab highlights the need for consistent protection across all stages of the authentication workflow.


## LAB 13- Broken brute-force protection, multiple credentials per request

## Lab Description :

![image](https://github.com/user-attachments/assets/36bca7b2-e086-4ca3-a9c4-6dfeea95da94)

## Solution

The first step is to analyze the functionality of the lab, starting with the login feature.

I attempted to log in with invalid credentials and repeated the request multiple times using Burp Suite Intruder with **Null payloads** to observe the server’s response to repeated failed login attempts.

![image](https://github.com/user-attachments/assets/ac9c770c-e602-4a2e-b27a-2d607f317d94)



### Analysis of Account Lockout Mechanism and JSON Request Data

I've observed that after three incorrect login attempts, an account lockout mechanism is triggered, preventing further attempts for one minute. Initially, the error message states "Invalid username or password," but after the third attempt, it changes to "You have made too many incorrect login attempts. Please try again in 1 minute(s)."

This behavior indicates that the lockout is **not based on specific usernames**. Instead, it appears to identify and track the client making the repeated failed attempts. This identification could be based on the client's IP address, or other unique characteristics used to distinguish one client from another.

To investigate whether the lockout was tied to HTTP headers, I performed an additional Burp Intruder run. During this run, I attempted to circumvent the lockout by:

* Modifying the `User-Agent` header for each request.
* Utilizing the `X-Forwarded-For` header to spoof the client's IP address.
* Removing or modifying existing cookie values.

However, none of these attempts were successful; the lockout consistently occurred after three failed attempts, regardless of the header manipulations. This suggests that the tracking mechanism is more sophisticated than a simple reliance on these common HTTP headers.

While subtle differences in error messages or response timings can sometimes reveal vulnerabilities, given that each lab is typically focused on a single, primary issue, I've opted to skip detailed analysis of such nuances to concentrate on more direct attack vectors.

A critical new observation, distinct from previous labs, is that the request data is not standard `POST` data but is formatted as a **JSON structure**. This is a significant detail as it implies the server processes login credentials from a structured JSON payload, which could influence how the lockout mechanism functions or how different attack techniques might be applied.

![image](https://github.com/user-attachments/assets/4cea2fa1-d7cb-4a8c-9503-821161b8f384)

The response reveals two important things:

1. The application encountered a case it does not handle properly, resulting in an error.
2. Any scenario that triggers unhandled behavior can potentially serve as an attack vector.

![image](https://github.com/user-attachments/assets/7458c525-587c-4681-808b-674a7d4dda08)

### Modifying the request

Sending 100 different password parameters results in a server error. So what happens if I supply a single password parameter that contains all the passwords in a list?( we can provide as many password as,I can in this case

![image](https://github.com/user-attachments/assets/fe7186f6-ee47-496b-ad8b-4c377642b256)

 Send the request. This will return a 302 response.

4 Right-click on this request and select Show Response in the browser. Copy the URL and load it in the browser. The page loads and you are logged in as carlos.

---


## LAB 14 - 2FA bypass using a brute-force attack

## Lab Description :

![image](https://github.com/user-attachments/assets/ac56412e-90a8-42a5-b77f-025025041668)


## Solution

For this attack, I used Burp Suite's **Session Handling** feature

### Step 1:

- Log in using the given credentials while Burp is running.
- When prompted for the 2FA code, enter random digits to intentionally fail the 2FA step.

- ![image](https://github.com/user-attachments/assets/c345d117-61f6-45f3-827f-9f1af5ec3948)

### Step 2: Configure Burp Session Handling with Macros

- Open Burp Suite.
- Go to **Project Options → Sessions → Session Handling Rules**.
- Click **Add** to create a new rule.

![image](https://github.com/user-attachments/assets/988bb52a-b57b-4747-8c07-70941bb398ae)

#### Macro Setup

1. **Create a Macro** to automatically fetch fresh CSRF tokens and handle the login sequence:
    - `GET /login` — to retrieve the CSRF token.
    - `POST /login` — to submit valid credentials.
    - `GET /login2` — to prepare for the 2FA step (which will be brute-forced using Intruder later).

This macro ensures that every time Burp Intruder sends a request, it has a valid CSRF token and an active session to work with.


![image](https://github.com/user-attachments/assets/eae3892e-77e0-4cfd-933c-248f53f0fa8a)


### Important Configuration: Include URLs in Scope

In **Burp Suite**, make sure to add all relevant URLs to the **scope**.

> **Note:** Including all URLs in scope ensures that the macro is executed for every request intercepted and sent by Burp Intruder. This guarantees that the CSRF token and session remain valid for each request during the brute-force attack.

![image](https://github.com/user-attachments/assets/12c8e939-324e-4baf-9c22-9c5b8f9596ef)


### Step 3: Recording Macros

The **Macro Recorder** in Burp Suite allows selecting requests directly from the Proxy history.

For this case, we select the following requests in sequence (using **Ctrl + Left-click**):

- `POST /login` — for submitting credentials.
- `POST /login2` — for submitting the 2FA code.
- `GET /login` — to retrieve a fresh CSRF token if needed.

These requests are added to the macro, ensuring Burp has a valid session and CSRF token before every Intruder request.

![image](https://github.com/user-attachments/assets/b7813df7-7389-4057-8749-a8b44de506e4)


This will , Retry to login after every try or we can say it will keep me logged in .

### STEP 3 

 SEND POST **/login2** to burp intruder , and add payload marker to 2FA parameter.

![image](https://github.com/user-attachments/assets/df874832-8eea-49ba-8b46-35c3bf3d64b0)

### STEP 4 → Give conncurrent request according to your choice

![image](https://github.com/user-attachments/assets/c4efc8e1-b800-402d-acc2-9f27b3b7902e)



### Step 4: Intruder Configuration

- Set **Maximum Concurrent Requests** to `1` to ensure only one request is sent at a time.
  
- Under the **Payloads** tab:
  - Select **Numbers** as the payload type.
  - Set the range from `0000` to `9999`.
  - Set the step to `1`.
  - Set the minimum and maximum integer digits to `4` (to ensure all 4-digit codes are generated).
  - Set maximum fraction digits to `0`.
  
This configuration will generate every possible 4-digit code for brute-forcing the 2FA.

### Step 5: Launching the Attack

- Start the Intruder attack.
- Monitor the responses and look for any request returning a **302** status code — this indicates a successful 2FA code.
  
Once a request with `302 Found` status is identified:

- **Right-click** on that request → **Show response in browser**.
- The session will open in the browser, and you will be successfully logged into the target account.

Then:

- Click on **My Account** to fully solve the lab.

> **Note:** You must send the request to the browser immediately after finding the `302` response. If you delay, the CSRF token may expire, and you will get an "Invalid CSRF" error.


![image](https://github.com/user-attachments/assets/51682e4f-35bf-4ea2-9fcf-a1def022628d)

