## Labs Covered

This write-up focuses on the following **EXPERT-level lab** from the PortSwigger Web Security Academy related to **Race Conditions**:

**6 Partial construction race conditions**  
<blockquote>
This lab shows how attackers can interfere with the partial creation of resources by triggering requests at specific times, gaining access to incomplete or inconsistent resource states.
</blockquote>

---

## LAB 6 - Partial construction race conditions

## Lab Description

![image](https://github.com/user-attachments/assets/7a5c8901-6c1e-46c5-ac66-e7438259ed8e)

## Overview

### Session-Based Locking and Partial Construction Race Conditions

Session-based locking mechanisms, such as PHP's native session handler module, process one request per session at a time, which can mask vulnerabilities. To detect these issues, send requests with different session tokens when sequential processing is observed.

Partial construction race conditions occur in applications where objects are created in multiple steps, creating a temporary exploitable state. For example, during user registration, a window exists between creating the user in the database and initializing their API key. This allows potential exploits by injecting input values that match uninitialized database values.

Framework-specific syntax can be leveraged for such exploits:
- In PHP, `param[]=foo` is equivalent to `param = ['foo']`.
- In Ruby on Rails, parameters with keys but no values are allowed.

Understanding these mechanisms is critical for identifying and mitigating security vulnerabilities.

## Solution

1 Firstly, when we start lab we can see below page.


![image](https://github.com/user-attachments/assets/1f56ffe9-bef0-4e49-8148-ad137b273eec)

2. The lab starts with a page that does not provide credentials. Attempt to create an account, but only emails with the `@ginandjuice.shop` domain are accepted.


![image](https://github.com/user-attachments/assets/b0f4718c-b6ac-4141-a14f-c9c6a6bd78c4)


3. Create an account using an `@ginandjuice.shop` email 

   ![image](https://github.com/user-attachments/assets/2c892792-02bb-47f6-a7e3-ed7b60eefe06)

4  Send the registration link to the email.

  ![image](https://github.com/user-attachments/assets/3e50a538-72af-47ec-99f5-2668048e800e)



5. Intercept the email registration process and send it to Burp Repeater.

   ![image](https://github.com/user-attachments/assets/2513fa77-b4f2-4b8d-a316-7d71d7adc781)

6. We can see the email which we have used to create email.
   
   - Note the email used for registration. Only one username and email are valid per registration. For a second registration, use a different email and username.

     ![image](https://github.com/user-attachments/assets/f30a1517-3c53-494b-a998-de1da0d1ee53)

7. Inspect the page and analyze the JavaScript to understand the token generation process.
 
    ![image](https://github.com/user-attachments/assets/3c9a49a9-1908-4c2b-9319-5cf5862863b0)

8. The URL shows a "confirm" endpoint to verify the email.

   ![image](https://github.com/user-attachments/assets/94d7d774-3a71-432e-9cd1-935e86b4cfd8)

9. Clicking the confirmation link results in an "Incorrect token" error.

    ![image](https://github.com/user-attachments/assets/4897e087-e4a1-405f-948d-2c31c6a9e5b8)

10. Send the confirm email request from HTTP history to Repeater.

    ![image](https://github.com/user-attachments/assets/5c3d19a7-853d-40e9-91b0-9f65be2b9cac)

11. Testing with a random token yields an "Invalid token" error.

    ![image](https://github.com/user-attachments/assets/76234c03-c184-4291-9e6d-1c8eea79ddbd)

12. Using no token results in a "Forbidden" message.

     ![image](https://github.com/user-attachments/assets/3ef71fdf-86ee-4e47-8f9f-dd5a8753e69a)

13. Using an empty array (`token[]=`) results in an "Invalid Array" error, indicating the server accepts an empty array but performs server-side validation.

    ![image](https://github.com/user-attachments/assets/3dff2213-efef-4fce-b64b-b282a071567e)

14. Group the registration and token confirmation requests in Repeater.

    ![image](https://github.com/user-attachments/assets/b8eba9ab-5488-4b4b-815a-a9efffa1dd09)

15. Sending them in parallel shows the token request reaches the server first, followed by the registration request, which is invalid since token generation and validation occur after registration.
    - Confirm request arrives first.
    

      ![image](https://github.com/user-attachments/assets/56c44a86-5433-432d-97a3-b84a6d01d29a)

     - Register request arrives later.

       ![image](https://github.com/user-attachments/assets/1073d091-6388-4094-a3fa-015e4956c32d)

16 . Send the registration request to Turbo Intruder.

 ![image](https://github.com/user-attachments/assets/9df92822-287b-4469-8bf6-e18c90f3b1eb)

17. Select "Race Single Packet" and modify the request as needed.

    ![image](https://github.com/user-attachments/assets/43f554ce-0b9e-40e9-99e7-0f519465709a)


18 . Copy the headers from the confirm token request and remove unnecessary headers.

  ![image](https://github.com/user-attachments/assets/d47bd1ed-9fe3-4af6-a827-43e69fb2ba0c)

19. Use the following modified code in Turbo Intruder:

  ![image](https://github.com/user-attachments/assets/a0534aa0-b7ee-4599-a04e-6382c3035309)

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, engine=Engine.BURP2)
    confirmationReq = '''POST /confirm?token[]= HTTP/2
Host: YOUR-LAB-ID.web-security-academy.net
Cookie: phpsessionid=YOUR-SESSION-TOKEN
Content-Length: 0
'''
    for attempt in range(20):
        currentAttempt = str(attempt)
        username = 'User' + currentAttempt
        # Queue a single registration request
        engine.queue(target.req, username, gate=currentAttempt)
        # Queue 50 confirmation requests - note that this may be sent in two separate packets
        for i in range(50):
            engine.queue(confirmationReq, gate=currentAttempt)
        # Send all queued requests for this attempt
        engine.openGate(currentAttempt)

def handleResponse(req, interesting):
    table.add(req)
```

20 . Set `%s` on the username field to fuzz the username.

![image](https://github.com/user-attachments/assets/3cdfaf96-ea58-48bd-a9c2-243c48ab91e5)

21. The `User4` (e.g., `han4`) account is successfully registered due to the race condition.

     ![image](https://github.com/user-attachments/assets/931e36c8-918a-42c9-965d-a3e5b6ce5ab2)

22. Log in with the `han4` username and the password provided in the registration request.

      ![image](https://github.com/user-attachments/assets/a6cb75b4-fa42-4ce4-b926-2f76861516f5)

24. Delete the `carlos` account, and the lab is solved.

    ![image](https://github.com/user-attachments/assets/00d24e81-d3fc-4577-be90-b0aaf2322dca)

