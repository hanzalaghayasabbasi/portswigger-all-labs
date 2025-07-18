## Labs Covered

This write-up focuses on the following **PRACTITIONER-level labs** from the PortSwigger Web Security Academy related to **Race Conditions**:

**Bypassing rate limits via race conditions**  
This lab shows how concurrent requests can overwhelm rate-limiting mechanisms, allowing attackers to bypass restrictions on the number of allowed requests.

**Multi-endpoint race conditions**  
This lab demonstrates how using multiple endpoints that modify shared resources simultaneously can lead to race conditions and inconsistent application states.

**Single-endpoint race conditions**  
This lab shows how a single endpoint, if accessed concurrently, can produce unintended behavior due to unsynchronized processing of shared resources.

**Exploiting time-sensitive vulnerabilities**  
This lab demonstrates how attackers can exploit timing windows in processes dependent on time-sensitive operations to bypass restrictions or create inconsistent states.

---

### LAB 2 - Bypassing rate limits via race conditions

### Lab Description

![image](https://github.com/user-attachments/assets/08c4357e-2c6d-4d05-b4a9-47969458ba31)

![image](https://github.com/user-attachments/assets/8ea42ebd-8135-47a0-ab9b-b6394b94e4f6)

```
123123
abc123
football
monkey
letmein
shadow
master
666666
qwertyuiop
123321
mustang
123456
password
12345678
qwerty
123456789
12345
1234
111111
1234567
dragon
1234567890
michael
x654321
superman
1qaz2wsx
baseball
7777777
121212
000000

```
# Overview:

## Detecting and Exploiting Limit Overrun Race Conditions with Turbo Intruder

In addition to Burp Repeater's native support for parallel execution, the **Turbo Intruder** extension has also been enhanced to support **single-packet attacks**. You can download the latest version of Turbo Intruder from the **BApp Store**.

### Why Use Turbo Intruder?

Turbo Intruder is ideal for more **complex race condition exploits**, such as:

- Multi-stage or retry-dependent attacks
- Staggered or precisely timed requests
- High-volume request flooding
- Full control via Python scripting

---

### Requirements:

1. **Target must support HTTP/2** — single-packet attacks are not compatible with HTTP/1.
2. Use:
   - `engine = Engine.BURP2`
   - `concurrentConnections = 1`

---

### Method: Single-Packet Attack in Turbo Intruder

You can queue multiple requests into a **named gate**, then release them all simultaneously to hit the race window with high accuracy.

#### Example Script:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        engine=Engine.BURP2
    )

    # Queue 20 requests in gate '1'
    for i in range(20):
        engine.queue(target.req, gate='1')

    # Open gate '1' to send all requests at once
    engine.openGate('1')
```


### Solution



# Lab Solution

There are two methods to solve the lab.

## Method 1: Through Burp Intruder

1. If we input three invalid attempts, the account will lock out for 1 minute.                                                                                                          ![image](https://github.com/user-attachments/assets/6d8c1942-e6c4-458b-80e9-3a812bb52527)

2. Log in with the username "wiener" and intercept the request in Burp.                                                                                                                 ![image](https://github.com/user-attachments/assets/f48eb4b6-2fbb-4731-bc3a-173da71ac050)

3. Send the request to Intruder.

     ![image](https://github.com/user-attachments/assets/bbc8057d-6390-42d7-8d78-72e01f8cba8b)

4. Change the username to "carlos" (the account whose password we want to obtain) and set the payload position in the password field.

    ![image](https://github.com/user-attachments/assets/2542746a-3588-483f-a240-495ebb74b552)

5. Configure the resource pool to send 30 requests concurrently.

   ![image](https://github.com/user-attachments/assets/1becf2f2-ef89-4a3f-b6ec-c5d76f50ca63)

6. Start the attack in Intruder. A 302 response indicates a successful race condition, and the password is found.
   
   ![image](https://github.com/user-attachments/assets/4bb3362a-efda-40de-be2e-34c9fc166c2d)

7. Log in with the obtained password for "carlos."
    
    ![image](https://github.com/user-attachments/assets/fc691f53-4c53-4e1d-94cf-b231af25b769)

8. Go to the admin panel, delete the "carlos" account, and the lab is solved.

    ![image](https://github.com/user-attachments/assets/1ae2836e-f930-4fe8-a5b2-9c995ee5172a)



## Method 2: Through Turbo Intruder

1. Follow the same initial steps as the first method, but send the request from the history to Repeater.
 
   ![image](https://github.com/user-attachments/assets/41e287b5-ded0-4914-b0e7-c610e05e3040)

2. Send the request to Turbo Intruder.
   
   ![image](https://github.com/user-attachments/assets/d93cf2fe-639d-41ba-8c04-ed6611e44f78)

3. Select the "Single Packet Attack" option.
   
   ![image](https://github.com/user-attachments/assets/362754fe-7978-4035-80cb-ed577905ca1e)

4. Paste the following password list script into the console log to retrieve the password from the list:

```javascript
var passwordList = `1231
abc123
football
monkey
letmein
shadow
master
666666
qwertyuiop
123321
mustang
123456
password
12345678
qwerty
123456789
12345
1234
111111
1234567
dragon
1234567890
michael
x654321
superman
1qaz2wsx
baseball
7777777
121212
000000`.split('\n')
```

5. The password list is now in list form.

   ![image](https://github.com/user-attachments/assets/036584e5-809b-4928-8d5a-2700749ced71)

6. Modify the script in Turbo Intruder, where `%s` represents the parameter to fuzz (the password).

7. Click "Attack."

   ![image](https://github.com/user-attachments/assets/c81ed70c-0f92-4616-865c-04d6c98396fd)



8. A 302 response indicates the password was successfully obtained.

    ![image](https://github.com/user-attachments/assets/f6ac544c-f135-4aca-b597-198da66f9152)

9. Log in with the obtained password for "carlos."
    
    ![image](https://github.com/user-attachments/assets/f0af19a7-6629-4c2b-9b02-19eff8dc7034)

10. Delete the "carlos" account from the admin panel, and the lab is solved.

   ![image](https://github.com/user-attachments/assets/15ae8322-0e01-45dc-ba14-5e77b73d4577)

   ![image](https://github.com/user-attachments/assets/1ae2836e-f930-4fe8-a5b2-9c995ee5172a)

---

### LAB 3 - Multi-endpoint race conditions

### Lab Description

![image](https://github.com/user-attachments/assets/ba546b8a-dfbd-4ab8-ad6c-1cb95b178db6)

## Overview

### Hidden Multi-Step Sequences

Hidden multi-step sequences in HTTP requests can lead to interactions with the same data, potentially exposing time-sensitive logic flaws in multi-step workflows. These vulnerabilities can be exploited through race condition attacks, extending beyond simple limit overruns. For instance, flawed multi-factor authentication (MFA) workflows may allow an attacker to complete the first login step with known credentials and then bypass MFA entirely by navigating directly to the application via forced browsing.

The following pseudo-code illustrates a website's vulnerability to a race condition variation of this attack:

#### Methodology

To detect and exploit hidden multi-step sequences, follow this methodology:

![image](https://github.com/user-attachments/assets/7774aa05-999b-440a-bb28-ed646e080d88)


1. **Predict Potential Collisions**  
   Testing every endpoint is impractical. After mapping the target site, narrow down the endpoints to test by asking:  
   - **Is this endpoint security-critical?** Many endpoints do not interact with critical functionality and can be skipped.  
   - **Is there collision potential?** Successful collisions typically involve two or more requests operating on the same record. For example, consider variations of a password reset implementation.
  
     ![image](https://github.com/user-attachments/assets/c267b553-31ee-4987-bdf6-179343b737c0)


2. **Recognize Clues in Endpoint Behavior**  
   Use Burp Repeater to benchmark endpoint behavior under normal conditions. Group requests and send them sequentially or in parallel to minimize network jitter. Look for deviations in responses or second-order effects, treating anomalies as potential indicators of vulnerabilities.

3. **Prove the Concept**  
   Understand the observed effects, eliminate unnecessary requests, and ensure replicability. Advanced race conditions may reveal unique structural weaknesses rather than isolated vulnerabilities.

### Challenges in Multi-Endpoint Race Conditions
Aligning race windows in multi-endpoint race conditions is complex due to network architecture delays and endpoint-specific processing variations. Factors like connection establishment and differences in endpoint processing times contribute to synchronization challenges. To mitigate this:  
- **Connection Warming**: Send inconsequential requests (e.g., a GET request to the homepage) to "warm up" the connection, helping distinguish backend connection delays from endpoint-specific factors.  
- In Burp Repeater, use the "Send group in sequence (single connection)" option, starting with a homepage GET request in the tab group, to observe and manage processing times effectively.

This approach enhances the accuracy of testing for race condition vulnerabilities in multi-step sequences.

### Solution


# Lab Solution

1. Log in with the provided account.
  ![image](https://github.com/user-attachments/assets/f69a16f5-6c50-464e-a819-93e2d4773868)

2. Purchase a gift card.

   ![image](https://github.com/user-attachments/assets/304ee40c-5cb2-4bc0-bdff-e79358f4361a)


3. After buying gift card we will get the coupoun.

   ![image](https://github.com/user-attachments/assets/a21bfc58-c51f-4e65-8178-5bba1f022d33)


4. You can see in blue color we have got a code after buying gift card


    ![image](https://github.com/user-attachments/assets/da3c0104-f49d-4143-9cb0-621753f08af3)


5. In HTTP history, observe three requests:
   - **GET /cart**: Retrieves information about items in the cart.
   - **POST /cart**: Adds items to the cart.
   - **POST /cart/checkout**: Processes the transaction for items in the cart.

     ![image](https://github.com/user-attachments/assets/aac9f970-5ebc-4dfa-8df8-60ea21a2ef42)

6. In Burp Repeater, test the **GET /cart** request with and without the session cookie:
   - Without the session cookie, only an empty cart is accessible.
   - This indicates:
     - The cart state is stored server-side in the session.
     - Cart operations are tied to the session ID or associated user ID.
   - This suggests potential for a collision.

     ![image](https://github.com/user-attachments/assets/020e2ae9-86e3-4110-9f70-7aab94a7b6e6)

7. Using the session, the **GET /cart** request shows the cart's contents.


     ![image](https://github.com/user-attachments/assets/af340dd0-4c97-45c7-a3d9-09016acbbbb5)

8. Create a group with two requests:
   - **POST /cart**
   - **POST /cart/checkout**


     ![image](https://github.com/user-attachments/assets/109e0542-56a5-4f5b-b41b-144249f6b4a6)

9 . Obtain the product ID of the Lightweight L33t Leather Jacket (product ID: 1).
      ![image](https://github.com/user-attachments/assets/6838d19c-9479-4a30-b10b-566092ceb75d)

10 In Repeater, modify the **POST /cart** request to set the `productId` parameter to 1 (Leather Jacket).

   ![image](https://github.com/user-attachments/assets/d00ea0f1-7e27-4dc2-9876-a22ec9d8f77c)


11. Send the grouped requests in parallel.

     ![image](https://github.com/user-attachments/assets/f0693cd9-0479-4f30-aa7b-c86e5f5601c3)

12. To address the issue, you should ensure that the gift card is in the cart before executing the request in parallel. If the leather jacket is not purchased but the gift card is, you should repeat the process by
    placing only gift cart in the cart again.
    During the parallel execution of requests, only the gift card will be present in the cart initially. This setup is crucial because the server assumes there's a gift card in the cart due to parallel requests.
    However,  due to the race condition, both the gift card and the leather jacket will end up being purchased.

    ![image](https://github.com/user-attachments/assets/6bdbb1c6-3e5e-4bfb-ad49-6216833ae6bf)


13. When the race condition is successfully exploited, the Leather Jacket is purchased, and the lab is solved.

    ![image](https://github.com/user-attachments/assets/856ad75f-be17-4db7-a578-a5e85cb77fba)


---

### LAB 4 - Single-endpoint race conditions

### Lab Description

![image](https://github.com/user-attachments/assets/2f041233-5ae1-4555-912f-6606e32b0539)

# Overview

## Abusing Rate or Resource Limits

When connection warming is ineffective for aligning multi-endpoint race windows, alternative methods can be used. With Turbo Intruder, introducing a short client-side delay is one option, but this requires splitting attack requests across multiple TCP packets, reducing reliability on high-jitter targets. A more effective approach is to abuse web server rate or resource limits by sending numerous dummy requests to trigger these security features.

![image](https://github.com/user-attachments/assets/912e935d-84b4-4c1f-9b38-13c5e4b97372)


## Exploiting Password Reset Collisions

In this scenario, sending two parallel password reset requests from the same session, but with different usernames, can cause a collision. For example:

- Send one request for the attacker's username.
- Send another for the victim's username simultaneously.

![image](https://github.com/user-attachments/assets/c6f67727-3eff-4d53-b5ef-75d5dd38c58c)

### Outcome
When all operations are complete, the session state may be:
- `session['reset-user'] = victim`
- `session['reset-token'] = 1234`

This results in the session containing the victim's user ID, but the valid reset token is sent to the attacker, enabling potential unauthorized access.

### Solution

# Lab Solution

1. Log in with the provided credentials.

   ![image](https://github.com/user-attachments/assets/c84048ec-eef3-49da-aaca-8bc849a5b49b)

2. Change the email address to `carlos@exploit...` to understand how the email change process works.

   ![image](https://github.com/user-attachments/assets/038bc734-29d2-4156-94aa-74c68407b644)

3. An email is sent with a "Click here to confirm" link to change the email to `carlos@exploit...`.

    ![image](https://github.com/user-attachments/assets/8aa42c2a-0317-4b05-bb4e-6bd2eaa6b6ab)

4. Clicking the link updates the email to `carlos@exploit...`.

   ![image](https://github.com/user-attachments/assets/9b47ee7f-9e51-4281-8056-15b7274b7f65)

5. Go to the HTTP history and send the email change request to Burp Repeater.

   ![image](https://github.com/user-attachments/assets/60e9a9d4-d8bb-4198-8ff4-daca06ae2da6)

6. In Repeater, create two tabs with different email addresses:
   - Tab 1: Email set to `king@exploit...`
   - Tab 2: Email set to `queen@exploit...`

      ![image](https://github.com/user-attachments/assets/568e11ee-a233-4ca5-b8ba-3382b08193a7)

     Queen email
     
      ![image](https://github.com/user-attachments/assets/974791e1-53e0-4363-ba0e-2412b84a8100)


7 . Group both requests to Group1

 ![image](https://github.com/user-attachments/assets/c5667fc9-b3f0-420e-8864-a385db9fef53)

8 . Configure them to be sent in parallel.

  ![image](https://github.com/user-attachments/assets/c5b68c00-3860-4e95-ac0c-9157f75eb8ff)

9 . Sending the group in parallel triggers a race condition on the server, causing the email to change to `queen@exploit...`.

 ![image](https://github.com/user-attachments/assets/48b2b2d9-5656-4b89-941a-929e448e5a58)

10 . An email is sent with a "Click here to confirm" link to update the email to `queen@exploit...`.

   ![image](https://github.com/user-attachments/assets/d6c739d8-3642-4326-b6d3-2cd2e39dbc7e)

11 . Clicking the link changes the email to `queen@exploit...`, achieving the race condition as the email was intended to change to `king@exploit...` but is set to `queen@exploit...`.

   ![image](https://github.com/user-attachments/assets/6d49419e-6121-4433-bb15-37a69b625d67)

12. Repeat the process to change the email to an address with admin access, such as `carlos@ginandjuice.shop`.
  
     - Change the email to `carlos@ginandjuice.shop` and send the requests in parallel, using another email like `king@exploit...`.
     
        ![image](https://github.com/user-attachments/assets/7b7fc169-3705-4b4f-b723-5a2cd4bb3d59)
       
13. Send the requests multiple times and refresh the browser, which will prompt a "Click here to confirm" link to change the email to `carlos@ginandjuice.shop`.

    ![image](https://github.com/user-attachments/assets/b9189aa3-2da4-404c-99f4-b594e6ce5bed)

 
14. Clicking the link updates the email to `carlos@ginandjuice.shop`, granting admin privileges.

    ![image](https://github.com/user-attachments/assets/7ef0ffe6-6e92-455a-b3f7-5da48f6898cd)

15. Verify that the email has been successfully updated.

    ![image](https://github.com/user-attachments/assets/f39fe595-53e1-415b-8332-6b166e4de233)

16. Delete the `carlos` account, and the lab is solved.

    ![image](https://github.com/user-attachments/assets/0b23ee83-81e9-4383-ba26-07660b315737)

---

### LAB 5 - Exploiting time-sensitive vulnerabilities

### Lab Description
![image](https://github.com/user-attachments/assets/8cae28ff-e814-4c2f-9920-847c63151a7d)

## Overview


### Time-sensitive attacks

Sometimes you may not find race conditions, but the techniques for delivering requests with precise timing can still reveal the presence of other vulnerabilities.
One such example is when high-resolution timestamps are used instead of cryptographically secure random strings to generate security tokens.
Consider a password reset token that is only randomized using a timestamp. In this case, it might be possible to trigger two password resets for two different users, which both use the same token. All you need to do is time the requests so that they generate the same timestamp.
### Solution

# Lab Solution

1. Click on "Forgot Password," which prompts for a username or email.

   ![image](https://github.com/user-attachments/assets/f8e3010b-a515-458a-9107-25dec20a2050)

   
2. Enter the username, sending a reset token to the `wiener` email.

    ![image](https://github.com/user-attachments/assets/30482c7b-9707-4b82-b722-0ed84cc83ed6)

   

3. Verify that the reset token is sent to the email.

  ![image](https://github.com/user-attachments/assets/4e615207-6654-48ed-987f-0216ff6ef402)

4. In the email server, locate the reset token. Clicking the link directs to the password reset page.

    ![image](https://github.com/user-attachments/assets/ba23cea6-a8e7-47b8-9f86-65f1609dd873)

5. The reset page prompts for a new password and confirmation.

    ![image](https://github.com/user-attachments/assets/0e7bf1f7-19fb-4514-b858-f3341af1b967)

6. In HTTP history, identify two requests:
   - **GET /forgot-password**: Navigates to the forgot-password section.
   - **POST /forgot-password**: Submits the username and CSRF token to send the password reset link.

     ![image](https://github.com/user-attachments/assets/51140d8d-4029-408b-8491-ca980de3e570)

7. Send the **POST /forgot-password** request to Burp Repeater twice, naming them `POST` and `POST1` (both identical).
    - Group the `POST` and `POST1` requests to send them in parallel.
   
       ![image](https://github.com/user-attachments/assets/b4dbaed1-72ad-4fce-b863-106640a0b520)


     Post request

      ![image](https://github.com/user-attachments/assets/947667ef-bc19-4848-8b53-64d1b768f5ce)


     Post1 request

     ![image](https://github.com/user-attachments/assets/aa489637-775b-4cda-9a38-76c3c72ee595)


8. Send a **GET /forgot-password** request with the session cookie.

    ![image](https://github.com/user-attachments/assets/2830d660-034c-41f0-8949-d3b92a78a6a6)

9. Send a **GET /forgot-password** request without the session cookie to obtain a new session cookie and CSRF token. These will be used for the race condition.

    ![image](https://github.com/user-attachments/assets/fb5f4512-9fda-4b88-ba10-91de6f84b5ea)

10. Send both **POST /forgot-password** requests in parallel. Initially, a significant difference in response times indicates sequential execution due to identical CSRF tokens and cookies, preventing a successful race condition.

  ![image](https://github.com/user-attachments/assets/9a0b3a9b-98ec-437a-b385-b81a3cfffd1b)

  

11. Replace the CSRF token and cookie in the `POST` request with the new values obtained from the **GET /forgot-password** request without the cookie.

    ![image](https://github.com/user-attachments/assets/f3023c8e-bf59-4417-a175-92a23ba429dc)

12. Resend both **POST /forgot-password** requests in parallel. Minimal difference in response times (similar for `POST` and `POST1`) indicates potential for a race condition.

    ![image](https://github.com/user-attachments/assets/3b51efad-4d9a-42da-a093-940cbe4902d1)

   post1
   
   ![image](https://github.com/user-attachments/assets/8b283b22-40a6-4b89-99b0-a839a6e894f8)


13. Modify the `POST` request to change the username to `carlos` to obtain `carlos`'s reset token via the race condition. The same token becomes valid for both `wiener` and `carlos` due to parallel requests.

    ![image](https://github.com/user-attachments/assets/6e18c722-37e4-418f-8230-eb325543264e)

14. Check the email server for the reset token message and copy it.

    ![image](https://github.com/user-attachments/assets/eee5572e-4757-4baa-a280-5838867ade60)

15. Attempt to use the token with the username `carlos`. If an "Invalid token" error appears, resend the parallel requests until successful.

    ![image](https://github.com/user-attachments/assets/95ecce95-59c9-4c4d-be46-009b477e40fe)

16. After several attempts, obtain a valid reset password token for `carlos` and use it to change the password.

   ![image](https://github.com/user-attachments/assets/827d0f4d-19f9-4182-a986-7bcfb272db66)



17. Log in with the new `carlos` password.

    ![image](https://github.com/user-attachments/assets/125b4b69-ef2c-4c83-b00f-87dc04d07baa)


   
18. Delete the `carlos` account, and the lab is solved.

      ![image](https://github.com/user-attachments/assets/acd240d4-8a3f-4d5d-86e0-a453ea8709e8)
