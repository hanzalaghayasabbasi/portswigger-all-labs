## Labs Covered

This write-up focuses on the following **PRACTITIONER-level labs** from the PortSwigger Web Security Academy:

**10 URL-based access control can be circumvented**  
 <blockquote>
  This lab demonstrates how attackers can bypass access control by directly accessing restricted URLs without proper authorization checks.
 </blockquote>

**11 Method-based access control can be circumvented**  
  <blockquote>
  This lab highlights how restricting access based on HTTP methods (e.g., GET, POST) can be ineffective if the server fails to enforce proper authorization on all methods.
</blockquote>

**12 Multi-step process with no access control on one step**  
<blockquote>
  This lab shows how incomplete access control checks on multi-step processes can allow attackers to bypass certain steps and perform unauthorized actions.
</blockquote>

**13 Referer-based access control** 
<blockquote>
  This lab illustrates the weakness of relying on the `Referer` header for access control, which can be easily manipulated by attackers to gain unauthorized access.
</blockquote>


---
## LAB 10 - URL-based access control can be circumvented


## Lab Description :

![image](https://github.com/user-attachments/assets/301db264-49e3-4bd9-a394-dc851c7059a6)



## Overview

### 1. `X-Original-URL`

This header indicates the original request URL before any modifications were applied by intermediate systems (such as proxies or load balancers). It can be compared to a note attached to a package during shipping, specifying the initial delivery address.

### 2. `X-Rewrite-URL`

This header reflects the rewritten or updated URL after the request has been modified by intermediaries. Continuing with the shipping analogy, this is like adding a new note to the package indicating that the delivery address has changed due to some decision or rule.

---

**Analogy Example:**

Imagine you order a package online:

- The original delivery address (your home address) represents the `X-Original-URL`.
- If the delivery company changes the address (e.g., redirects it to a nearby pick-up center), the new address represents the `X-Rewrite-URL`.




## Solution :

When the lab website loads, we immediately see the **Admin panel** link present.

![Admin Panel](https://github.com/user-attachments/assets/8e3f65ac-c5a3-4c9d-8cdf-52093e3c32c6)

When we click it, we get **Access Denied**.

![Access Denied](https://github.com/user-attachments/assets/a7f361d6-6b5a-4187-8a01-47e11f3d152a)

We capture the request in Burp. It looks like:

![Captured Request](https://github.com/user-attachments/assets/1da7e28a-9158-4eea-85d8-3b8f67df30fa)


#### Actual request - 

![image](https://github.com/user-attachments/assets/de91006f-62cc-4cf5-8575-2f496161f1f1)



#### Modified request

- Add the `X-Original-Url: /admin/delete` header
- Provide the `username=carlos` parameter as it is in the real query string.

![image](https://github.com/user-attachments/assets/f0fe6a38-417f-4252-b9a9-fe187fa08c67)




![image](https://github.com/user-attachments/assets/5618c98a-227a-47c8-98f9-595c9f5a878a)

---
## LAB 11 - Method-based access control can be circumvented

## Lab Decription :

![image](https://github.com/user-attachments/assets/e816e85a-801f-4347-a1a7-daf550c9005c)


## Solution :
.


This lab provides the administrator credentials to analyse the workflow of granting and revoking administrative permissions to users. It basically is just a form to select a user and using an Upgrade or Downgrade button:

***Our goal is to exploit the flawed access controls to promote ourself (wiener) to become an administrator.***

Log in using an admin account, then access the admin panel to promote the user [Normal].

![image](https://github.com/user-attachments/assets/fef2120b-42e2-42f6-8e16-71813db1c4f5)


So we can try to perform the role changing action as wiener by pasting the cookie value of wiener in the request made by admin to change the privileges.

So we change the cookie value of admin with wiener & send the request, we get the response as **401 - Unauthorized**

![image](https://github.com/user-attachments/assets/26d38b8b-0d6b-46d6-aea3-79ccf1d7726b)


***Response:***

![image](https://github.com/user-attachments/assets/6373bf32-0156-478d-a466-0fbcdc06ed63)



Since this lab is based on Method-Based-Access control bypass, we can try to change the request from **POST** to **GET**. We can do this by `Right click on request` -> Click `Change request method` option.

Now it changes to a *GET* request,

![image](https://github.com/user-attachments/assets/d51a6d2a-6283-4477-826f-1c812f5c6c84)


***Response:***

![image](https://github.com/user-attachments/assets/09c734da-c56c-4aff-b988-ff4c8f60bb05)


Response displays ***302** Found with directory location ***/admin***, which means the URL function has successfully upgraded the user with username wiener to admin.

There is an admin panel that shows the wiener account has been promoted to admin.


![image](https://github.com/user-attachments/assets/dac80e2d-0220-45d6-9319-c94e94798031)


---

## LAB 12 - Multi-step process with no access control on one step


## Lab Description :

![image](https://github.com/user-attachments/assets/eb7f1e0e-a906-4340-9d7b-adb0b6698f51)
)


## Solution :

> Mostly developers implement strong acces controls in the first step but fail to ensure it in the subsequent steps , so we can take advantage of that to perform privilege escalation.


After loging as administrator we can see below page

![image](https://github.com/user-attachments/assets/a783158d-ea3f-40f4-af0e-de1c8a2e7e0d)


Once logged in , we can go to admin panel & modify other user's privileges.

We need to upgrade wiener as admin by flawed multistep process, so lets now poke around with wiener.

![image](https://github.com/user-attachments/assets/1aec5f0e-29f9-4420-95a0-a8866ca3c12e)


We get a 401 unauthorized error.

![image](https://github.com/user-attachments/assets/783f9d75-de65-4ea0-9061-0d06e7cd8392)

If we try to upgrade ourself **(wiener)** by changing the cookie value of admin to non admin in the request of first step , with the confirmed parameter:

![image](https://github.com/user-attachments/assets/96757371-e322-4ab1-90cc-f5688b3907fa)


We get a redirection and then an 302 response with admin access:

![image](https://github.com/user-attachments/assets/98c26005-102c-46ad-ba75-52d464d67d60)



So Now the admin panel is accessible for wiener now:

![image](https://github.com/user-attachments/assets/806f0f48-e414-437c-95a8-c64c2b046bdc)



Thus we solved the lab ,

![image](https://github.com/user-attachments/assets/2fca8361-1265-4757-b6f8-3bb99b6386d8)



---
## LAB 13 - Referer-based access control

## Lab Description :

![image](https://github.com/user-attachments/assets/98351215-dc9f-4809-a178-4b256ea0fa12)

## Solution:

The process to upgrade the user is generated from the admin panel with a GET request:

![image](https://github.com/user-attachments/assets/13af7660-cf28-4934-b963-3b42f222990e)


But with **“carlos”** we get an unauthorized error:

![image](https://github.com/user-attachments/assets/d5a83eaf-3e14-435a-a4a3-277765037300)

It works chaning the **“Referer”** header to **/admin** and username to **carlos**.

![image](https://github.com/user-attachments/assets/170c2db5-d20a-46de-9f90-baf6439bca6c)

Thus we solved the lab by upgrading ourselves(wiener) to higher privilege.

![image](https://github.com/user-attachments/assets/80f84adf-83ea-4d66-ba21-76154b515f78)








