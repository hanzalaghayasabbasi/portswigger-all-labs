## Lab Covered

This write-up focuses on the following **EXPERT-level** lab from the PortSwigger Web Security Academy:

 **2 Exploiting server-side parameter pollution in a REST URL**
<blockquote>
This lab demonstrates how attackers can manipulate REST-style URLs to exploit server-side parameter pollution (SSPP) vulnerabilities — potentially leading to unauthorized access, logic bypasses, or information disclosure.
</blockquote>

---

## LAB 5 - Exploiting server-side parameter pollution in a REST URL

### Lab Description :

![image](https://github.com/user-attachments/assets/7141ec2f-2fdd-499c-9498-053903a75070)



### Overview
---
RESTful APIs often embed **parameter names and values directly within the URL path** instead of using traditional query strings. Understanding how these paths are structured is crucial for identifying potential vulnerabilities. For example, in `/api/users/123`, `/api` is the root endpoint, `/users` represents the resource, and `/123` is the parameter (an identifier for the user).

## Exploiting Server-Side Parameter Pollution
---
Attackers can manipulate server-side URL path parameters to exploit an API. This vulnerability occurs when an application processes or constructs internal server-side requests based on user-supplied input in the URL path without proper sanitization.

### Testing Methodology
To test for this, you can introduce **path traversal sequences** within user-controlled parameters in the URL and observe the application's response to see if it modifies the intended path.

**Scenario Example:**

Consider an application that lets you edit user profiles based on their username. Requests are sent to:


``` GET /edit_profile.php?name=peter ```


This client-side request translates into a server-side request like this:


``` GET /api/private/users/peter ```


To test for server-side parameter pollution, you could submit a URL-encoded path traversal sequence as the value of the `name` parameter:

``` GET /edit_profile.php?name=peter%2f..%2fadmin ``` 


Here, `peter%2f..%2fadmin` decodes to `peter/../admin`.

**Potential Server-Side Outcome:**

This manipulated request might result in the following server-side request:

``` GET /api/private/users/peter/../admin ```


If the server-side client or back-end API normalizes this path (i.e., resolves the `../` sequence), it could incorrectly resolve to:


``` /api/private/users/admin ```

This successful path manipulation could allow an attacker to **access or modify resources intended only for an administrator**, demonstrating a server-side parameter pollution vulnerability.

---

## Solution :

As we can see when we start lab we navigate to  Login page we see forget Password option:

![image](https://github.com/user-attachments/assets/5090c073-36a0-43ef-93c7-f0963ac3d113)

When we click on forget Password,It ask us Invalid route.

![image](https://github.com/user-attachments/assets/79c888b7-752d-4f2d-bba9-3c4e0ae6c355)

We can try to submit ***administrator*** username which exist on backend database, So we get 200 reponse if we input random username it will gives us reponse username doesnot exist

![image](https://github.com/user-attachments/assets/cb762746-229c-4cdb-a8a8-7d3244f25954)

I applied ***username=administrator#***. It asked to include API definition.

![image](https://github.com/user-attachments/assets/9bc412dd-e068-4b6a-ab5c-cc0698c33739)

Url encode it but same result

![image](https://github.com/user-attachments/assets/79c0e8ca-fc3b-49d4-b95a-ca2828ab4f61)

Change username to ***./administrator*** then send the request.

Notice that this returns the original response. This suggests that the request may have accessed the same URL path as the original request. This further indicates that the input may be placed in the URL path

![image](https://github.com/user-attachments/assets/b9216782-04d8-427f-9f11-0499d6e5822b)

Change the value of the username parameter from ./administrator to ../administrator, then send the request.
Notice that this returns an Invalid route error message. This suggests that the request may have accessed an invalid URL path.

![image](https://github.com/user-attachments/assets/b46d9fd4-0b45-422c-8d23-3991c90bd35c)

Incrementally add further ../ sequences until you reach ../../../../%23 Notice that this returns a Not found response. This indicates that you've navigated outside the API root.

![image](https://github.com/user-attachments/assets/e30e1364-d817-458d-9e4a-21ad0922fdaf)


At this level, add some common API definition filenames to the URL path. For example, submit the following:
***username=../../../../openapi.json%23***


![image](https://github.com/user-attachments/assets/bda07e13-e6db-4c51-96a9-34093c4c0dac)


Notice that this returns an error message, which contains the following API endpoint for finding users:

This endpoint indicates that the URL path includes a parameter called field.

In the above route, we can see there's a parameter called field. It seems like it's referring to the user object's attribute (field)!

```/api/internal/v1/users/{username}/field/{field}```



Add email as the value of the field parameter:

```username=administrator/field/email%23```

Send the request. Notice that this returns the original response. This may indicate that the server-side application recognizes the injected field parameter and that email is a valid field type.


![image](https://github.com/user-attachments/assets/5aadd8b5-eb2d-4757-8a2e-bd320d65afb3)

As expected, it returned the username value!

Moreover, by viewing the source page of ***/forgot-password***, we can see that there's a JavaScript file being loaded:

![image](https://github.com/user-attachments/assets/2a55b9c9-29e9-426d-8919-1de49c5ef78d)


Change the value of the field parameter from email to ***passwordResetToken***:

```username=administrator/field/passwordResetToken%23```

Send the request. Notice that this returns an error message, because the ***passwordResetToken*** parameter is not supported by the version of the API that is set by the application.


![image](https://github.com/user-attachments/assets/cc8fe458-88ad-4c01-89b5-0ed50d15046a)


Using the ***/api/*** endpoint that you identified earlier, change the version of the API in the value of the username parameter:

```username=../../v1/users/administrator/field/passwordResetToken%23```

Send the request. Notice that this returns a password reset token. Make a note of this

![image](https://github.com/user-attachments/assets/0b161e79-dac1-49c0-8802-f931c10b4073)

Nice! We got the reset token (4auv4tt19lgppm9cnqa9j4opc1jk5vfb)

Now can send a GET request to ***/forgot-password*** with parameter ***passwordResetToken=4auv4tt19lgppm9cnqa9j4opc1jk5vfb*** to reset administrator's pasword:

![image](https://github.com/user-attachments/assets/b7420add-ff4f-4c73-946a-34c185199480)



Change the Password .

![image](https://github.com/user-attachments/assets/af1723ab-9eb4-41bc-8fbc-3587070fba84)

login as admin 

![image](https://github.com/user-attachments/assets/13589172-3638-4c20-b10d-79d2c9ff39f5)

Delete the carlos user

![image](https://github.com/user-attachments/assets/c958e386-179c-4acf-a2d3-2f66c1aa9f9e)


lab is solved

![image](https://github.com/user-attachments/assets/e398034e-96e1-4689-a119-5286636c35b7)


