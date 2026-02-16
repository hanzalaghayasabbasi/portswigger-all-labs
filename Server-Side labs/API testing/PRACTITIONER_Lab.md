## Labs Covered

This write-up covers **Three PRACTITIONER-level labs** from the PortSwigger Web Security Academy related to API exploitation and testing:

**2 Exploiting server-side parameter pollution in a query string**

<blockquote>
This lab demonstrates how manipulating query string parameters can lead to server-side parameter pollution, potentially allowing unauthorized actions or information disclosure.
</blockquote>

**3 Finding and exploiting an unused API endpoint**  
<blockquote>
This lab shows how attackers can discover and abuse undocumented or unused API endpoints that may expose sensitive functionality or data.
</blockquote>

**4 Exploiting a mass assignment vulnerability** 
<blockquote>
This lab illustrates how improper handling of object properties in API requests can be exploited through mass assignment, allowing attackers to modify unintended data fields.
</blockquote>

---


## LAB 2 - Exploiting server-side parameter pollution in a query string

## Lab Description :

![image](https://github.com/user-attachments/assets/e6f6680b-dced-4327-b912-c79d53575c87)


## Overview

Server-side parameter pollution can occur when user-supplied query parameters are reflected into internal API requests. By manipulating query parameters, it's possible to inject, override, or truncate server-side requests.

---

## Test Scenarios

### 1. Truncating Query Strings

Use a URL-encoded `#` (`%23`) to attempt truncation:

```
GET /userSearch?name=peter%23foo&back=/home
```

This may result in:

```
GET /users/search?name=peter#foo&publicProfile=true
```

**Note:** Always URL-encode `#`. If not encoded, the browser treats it as a fragment and doesn't send it to the server.

**Indicators:**

* If `peter` is returned, truncation may have occurred.
* If an "Invalid name" error appears, `foo` may have been included in the name.

**Goal:** Bypass conditions like `publicProfile=true` to access restricted data.

---

### 2. Injecting Invalid Parameters

Use URL-encoded `&` (`%26`) to inject new parameters:

```
GET /userSearch?name=peter%26foo=xyz&back=/home
```

Results in:

```
GET /users/search?name=peter&foo=xyz&publicProfile=true
```

**Indicators:**

* No change in response: parameter injected but ignored.
* Error or altered response: parameter processed.

---

### 3. Injecting Valid Parameters

Inject known valid parameters (e.g., `email`):

```
GET /userSearch?name=peter%26email=foo&back=/home
```

Results in:

```
GET /users/search?name=peter&email=foo&publicProfile=true
```

**Indicators:** Look for changes in behavior indicating the parameter was processed.

---

### 4. Overriding Existing Parameters

Inject duplicate parameter names:

```
GET /userSearch?name=peter%26name=carlos&back=/home
```

Results in:

```
GET /users/search?name=peter&name=carlos&publicProfile=true
```

**Backend behavior:**

* **PHP:** Last parameter wins (`name=carlos`)
* **ASP.NET:** Parameters combined (`peter,carlos`)
* **Node.js/Express:** First parameter wins (`name=peter`)

**Exploit Potential:** Override with privileged usernames (e.g., `name=administrator`) to escalate access.

---

## Solution :

Visit the `My-Account` page, click on `forgot password`. 
Enter any username & capture the request.

![image](https://github.com/user-attachments/assets/d7d82d79-3ba6-4def-bef3-c07db202e71b)

The server responds with **Invalid username**.

### Server side parameter pollution -

What if we give value of username as `administrator`?

This time we get this response which confirms that administrator account exists.

![image](https://github.com/user-attachments/assets/6eeec8f6-70c8-4319-aeba-4fe5821549c6)

Upon adding a `#` at the end of the username, the server responds differently.

> URL encode the special characters else the frontend will not send the entire url to backend.

![image](https://github.com/user-attachments/assets/31bccae7-202e-4977-b722-984664c4fe91)

So from this we can understad that there might be a parameter called `**Field**`

Upon adding `&a=b`, the server responds differently again - `"error": "Parameter is not supported."`

![image](https://github.com/user-attachments/assets/e4ee428b-652e-471b-9d84-d862a971e17c)

This is a good indication that the backend server does process the parameter.

Now we can try sending any invalid value to field parameter (`**&field=test#**`) to check what the server responds.

### Hidden parameter in JS file -

The `a` JS file contains the following code which reveals a hidden parameter called `reset_token`.

```c
   const resetToken = urlParams.get('reset-token');
    if (resetToken)
    {
        window.location.href = `/forgot-password?reset_token=${resetToken}`;
    }
```

Now in the field parameter we can enter this - `**&field=reset_token#**`.

![image](https://github.com/user-attachments/assets/c7592ad7-d05e-44da-9d17-3f6b4b74ea29)

Now having the passord reset token for the administrator user, we can perform a GET request to `https://0a5200b30487309981671bc100890068.web-security-academy.net/forgot-password?reset_token=0envuvi6f1vnz0o6m7az4iykrixayq20` url to reset the admin's password.

We now get a page to set a new password for the admin user.

After resetting, we can login ad administrator.

![image](https://github.com/user-attachments/assets/dcd90b6b-f801-4fd9-bbfb-5051b2232900)

Goto **Admin panel** & delete the user carlos to solve the lab.

![image](https://github.com/user-attachments/assets/8606f475-2f46-45ca-a5b1-32ab5e6cf60e)

---
## LAB 3 -  Finding and exploiting an unused API endpoint

## Lab Description :

![image](https://github.com/sh3bu/Portswigger_labs/assets/67383098/f226880c-87cd-442a-981a-33e0b956b489)

## Overview

This guide outlines techniques for identifying and interacting with API endpoints during a security assessment or penetration test.

---

## Identifying API Endpoints

Even when API documentation is available, it may be outdated or incomplete. Actively browsing applications that use the API can reveal additional information.

- Use **Burp Scanner** to crawl the application.
- Manually investigate interesting attack surfaces using **Burp's browser**.
- Look for URL patterns indicating API endpoints (e.g., `/api/`).
- Inspect JavaScript files for references to additional endpoints. Use the **JS Link Finder BApp** or manually review JavaScript files within Burp.

---

## Interacting with API Endpoints

Once endpoints are identified, interact with them using **Burp Repeater** and **Burp Intruder** to:

- Observe API behavior.
- Test different HTTP methods and media types.
- Analyze error messages and responses for clues to construct valid requests or find vulnerabilities.

---

## Identifying Supported HTTP Methods

Different API endpoints may support multiple HTTP methods:

- **GET** – Retrieves data.
- **PATCH** – Applies partial changes.
- **OPTIONS** – Retrieves supported methods.

### Example: Supported methods for `/api/tasks`

```
GET /api/tasks        -> Retrieves task list.
POST /api/tasks       -> Creates new task.
DELETE /api/tasks/1   -> Deletes task with ID 1.
```


Use **Burp Intruder's HTTP verbs list** to cycle through potential methods automatically.

> **Note:** When testing HTTP methods, target low-priority objects to minimize unintended consequences.

---

## Identifying Supported Content Types

API endpoints often expect data in a specific format. They may therefore behave differently depending on the content type of the data provided in a request. Changing the content type may enable you to:

- Trigger errors that disclose useful information.
- Bypass flawed defenses.
- Take advantage of differences in processing logic.  
  For example, an API may be secure when handling JSON data but susceptible to injection attacks when dealing with XML.

> To change the content type, modify the `Content-Type` header, then reformat the request body accordingly.  
> You can use the **Content Type Converter BApp** to automatically convert data submitted within requests between XML and JSON.

---


## Solution :

Login as wiener using the provided credentials - `wiener:peter`

 Goto leather jacket and can see the price and our credit

![image](https://github.com/user-attachments/assets/369eb7c2-c37e-4a79-91d4-f4c9b3278585)

Try to buy the leather jacket it says not enough store credit giving

![image](https://github.com/user-attachments/assets/5387e3ab-e376-456a-9ce5-b03cf744b9ab)

Upon adding the leather jacket to cart, the following API request is sent.

![image](https://github.com/user-attachments/assets/7de6edcd-7438-4ed8-ae11-123ee51cb9a1)

Let's now check which HTTP methods are supported by the API by sending an `OPTIONS` request.

![image](https://github.com/user-attachments/assets/822560a2-feb0-4940-938f-848dec806080)

From the response we can see that the API responds - `**"error":"Only 'application/json' Content-Type is supported"**`.

![image](https://github.com/user-attachments/assets/ee0e3201-c019-4bfa-b87e-b13c83fdb4cd)

So let's change the content type to `application/json` using **Content-Type Converter extension** & send the request.

![image](https://github.com/sh3bu/Portswigger_labs/assets/67383098/765e317a-f085-46b0-baaa-91d300c1091e)

Now the API responds - **`"error":"'price' parameter missing in body"`**

So now let's set the price parameter in the body of the request to **0** & see what happens. And 
Open below request in orginal session and can see that price has become 0.

![image](https://github.com/user-attachments/assets/934ac432-6a84-456d-973c-f1600fbe8b60)

The request is successful & the price might have changed. Checking the home page confirms that the price of the jacket is now **$0**.

![image](https://github.com/user-attachments/assets/c37d0848-9ea9-4214-8ef2-f6f031960e73)

Now we can order the jacket & solve the lab.

![image](https://github.com/user-attachments/assets/9c99065e-2285-4ccf-84f4-bc4371eefc30)

---
## LAB 4 -  Exploiting a mass assignment vulnerability

## Lab Description :

![image](https://github.com/sh3bu/Portswigger_labs/assets/67383098/3ecb8c6e-4cda-4347-8943-023251558d74)

## Overview :

### Mass assignment vulnerabilities

Mass assignment (also known as auto-binding) can inadvertently create hidden parameters. It occurs when software frameworks automatically bind request parameters to fields on an internal object. Mass assignment may therefore result in the application supporting parameters that were never intended to be processed by the developer.

### Identifying hidden parameters
Since mass assignment creates parameters from object fields, you can often identify these hidden parameters by manually examining objects returned by the API.

For example, consider a PATCH /api/users/ request, which enables users to update their username and email, and includes the following JSON:

```json
{
    "username": "wiener",
    "email": "wiener@example.com",
}
```
A concurrent GET /api/users/123 request returns the following JSON:

```json
{
    "id": 123,
    "name": "John Doe",
    "email": "john@example.com",
    "isAdmin": "false"
}
```

This may indicate that the hidden id and isAdmin parameters are bound to the internal user object, alongside the updated username and email parameters.

### Testing mass assignment vulnerabilities
To test whether you can modify the enumerated isAdmin parameter value, add it to the PATCH request:

```json
{
    "username": "wiener",
    "email": "wiener@example.com",
    "isAdmin": false,
}
```

In addition, send a PATCH request with an invalid isAdmin parameter value:

```json
{
    "username": "wiener",
    "email": "wiener@example.com",
    "isAdmin": "foo",
}
```

If the application behaves differently, this may suggest that the invalid value impacts the query logic, but the valid value doesn't. This may indicate that the parameter can be successfully updated by the user.

You can then send a PATCH request with the isAdmin parameter value set to true, to try and exploit the vulnerability:

```json
{
    "username": "wiener",
    "email": "wiener@example.com",
    "isAdmin": true,
}
```

If the isAdmin value in the request is bound to the user object without adequate validation and sanitization, the user wiener may be incorrectly granted admin privileges. To determine whether this is the case, browse the application as wiener to see whether you can access admin functionality.

## Solution :

Login as wiener using the provided credentials - `wiener:peter`

![image](https://github.com/user-attachments/assets/0a931d46-779e-474e-a210-1e69c044d8eb)

The below we can see the price of leather jacket

![image](https://github.com/user-attachments/assets/f08e2bdd-1442-4cdd-a05c-8ce7ea5eb3b9)


I try to buy the jacket but failed

![image](https://github.com/user-attachments/assets/978b9d5d-1258-437a-96ae-293cce064b5d)

Add the leather jacket to cart. Now while checkout, the broswer sends the following API request.

![image](https://github.com/user-attachments/assets/6851c41b-17a4-4c62-b309-4078d6e696e2)



Then I identfied methods supported by ***api/checkout*** using ***OPTIONS***

![image](https://github.com/user-attachments/assets/b3ba9c38-c34b-4cc6-9112-41fbe770bd7a)



So from the Get form above 4 image request we can see the json is send back and post request is supported as we can see in 5 image above, So we will create payload which will submit the 100 discount for product 1,So we can buy it below is the payload

```json
{
 "chosen_discount":{
 "percentage":100
 },
 "chosen_products":[
 {
 "product_id":"1",
 "quantity":1
 }
 ]
} 
```

As we can see that sending below request gives us created response,Now I open this request in orignal session than lab is solved

![image](https://github.com/user-attachments/assets/1c14b0c7-6223-44bd-91e8-6d916bf92976)



Now in the checkout page we can see that the discount has been applied successfully & thus the lab is solved.

![image](https://github.com/user-attachments/assets/6b1d0c76-814a-41d0-95e9-b085eb930567)








