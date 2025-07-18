## Labs Covered

This write-up includes the following **PRACTITIONER-level labs**:

* **Low-level logic flaw**
  This lab shows how attackers can exploit detailed flaws in application logic to bypass intended restrictions or gain unauthorized access.

* **Inconsistent handling of exceptional input**
  This lab demonstrates how inconsistent validation of unusual or unexpected input can be exploited by attackers.

* **Weak isolation on dual-use endpoint**
  This lab shows how endpoints that serve multiple purposes without proper isolation can be abused by attackers.

* **Insufficient workflow validation**
  This lab demonstrates how flaws in validating user workflows can be used to bypass business logic controls.

* **Authentication bypass via flawed state machine**
  This lab shows how attackers can exploit weaknesses in state management to bypass authentication mechanisms.

* **Infinite money logic flaw**
  This lab demonstrates how logical flaws in financial transaction systems can allow attackers to generate infinite funds.

* **Authentication bypass via encryption oracle**
  This lab shows how attackers can abuse encryption oracles to bypass authentication mechanisms.

---


## LAB 5 - Low-level logic flaw

### Lab Description :

![image](https://github.com/user-attachments/assets/6c40b6b0-8e4f-42bd-83b2-c94692a0719e)


### Solution :

Add an item to the shopping cart; at this point, the maximum quantity is set to **99**

![image](https://github.com/user-attachments/assets/44c48447-52e1-45f1-a996-bd4ff344923e)

## 🔄 Null Payloads for Repeated Requests

This enables you to generate payloads whose value is an **empty string**. You can use this to repeatedly issue the **base request unmodified** — you don't need to configure payload positions.

You can use this payload type for a variety of attacks, for example:

- Harvesting cookies for sequencing analysis
- Repeating logic-based requests for cumulative effects

---

### 🧪 Example Attack Scenario

Now, we will send the value `99` again and again so that the **quantity value becomes negative** due to flawed backend handling. 

In Burp Suite Intruder:

- Set **Payload type** to: `Null payloads`
- Set **Attack type** to: `Sniper` (or suitable mode)
- Set **Payload setting** to Continue Indefinitely:  



This will cause the base request (with quantity = 99) to be sent repeatedly, exploiting logic flaws in the server's price calculation or stock handling.


![image](https://github.com/user-attachments/assets/e5c077bc-3ba1-4d84-b283-745bdafa7539)

Refresh the shopping cart and observe that the price has become negative:


![image](https://github.com/user-attachments/assets/73761f0d-3f73-412b-8f44-8f927abaa2b3)

Next, adjust the quantity to precisely control the amount between 0 and 100 or how you like.


![image](https://github.com/user-attachments/assets/fc670827-61bb-4458-8be4-3cbbadfc89c9)


---

## LAB 6 - Inconsistent handling of exceptional input

### Lab Description :


![image](https://github.com/user-attachments/assets/c6da9d85-f426-4b5d-96fc-cad3b58a4194)


## Solution :

### Finding Admin Panel

First, you need to locate the URI of the admin panel to delete the user "carlos."

Go to Target -> Sitemap.

Right-click on the lab domain.

Select Engagement tools -> Discover content to find available pages and directories on the website.

![image](https://github.com/user-attachments/assets/deadaa1a-d9da-4774-bf20-06c6eff025ad)

When we try to browse to `/admin`, it says only persons belonging to `DontWannaCry` company can access this page.

![image](https://github.com/user-attachments/assets/5b6fa5da-e764-4ee8-b762-8db4f87625ec)


### Account Registration

Go to the registration page to create an account with the email ID given to us:

`attacker@exploit-0ab1009903bcf40b8008753f01b300db.exploit-server.net`

On the registration page, it is mentioned that we can use `@dontwannacry.com` if we are an employee of that company.


![image](https://github.com/user-attachments/assets/10c582b9-a8df-4964-a755-502accad42a4)


Create an account with very long email address ending with **@exploit-0ab1009903bcf40b8008753f01b300db.exploit-server.net**. 

Example - `very-long-string@YOUR-EMAIL-ID.web-security-academy.net`

> NOTE - The very-long-string should be at least 200 characters long.

So I created an account with a very long string - `aafafasighfiyuqabryuawgfibasifnkajsdbgiuafgijaeboifnaijfaokjfiuahfjiahgr90ipqjro89sygfduygsfdtuvdtGUYEDFGWYTDVUYVDuyGDUYucvuavcuyvauyvdfuaycvuayvcuyasvcuyavcuyavcuucauvcuayvclu2o3i1hri97uuc89273r89hiug987niuch89qn397yr89hiu7ay89qah45uiyr0q@exploit-0ab1009903bcf40b8008753f01b300db.exploit-server.net`

![image](https://github.com/user-attachments/assets/8c7cda01-7306-42b0-9096-a6497b47e3ea)

After completing the registration, a confirmation email is received.


![image](https://github.com/user-attachments/assets/faa3451e-d8af-408c-94e8-69f45bcfc10a)


Clicking the link in the email completes the registration successfully.

![image](https://github.com/user-attachments/assets/1f445209-0101-427f-96a4-a2ad74b49457)

### Login and Email Truncation

Now, log in as the user using the credentials we created:

` Username: test1
  Password: 1234 `

Once logged in, we receive a welcome message. However, it's important to note that the **email address was truncated to 255 characters**, as shown below:


```
aafafasighfiyuqabryuawgfibasifnkajsdbgiuafgijaeboifnaijfaokjfiuahfjiahgr90ipqjro89sygfduygsfdtuvdtGUYEDFGWYTDVUYVDuyGDUYucvuavcuyvauyvdfuaycvuayvcuyasvcuyavcuyavcuucauvcuayvclu2o3i1hri97uuc89273r89hiug987niuch89qn397yr89hiu7ay89qah45uiyr0q@exploit-0ab1009
```


This indicates that the backend is enforcing a **maximum character limit (likely 255)** for email addresses, possibly truncating values at the database or application level.

![image](https://github.com/user-attachments/assets/8455e9c3-3198-41eb-92f1-13ac5aa1ed85)

#### KEY INFORMATION TO NOTE

- **Total characters in original email used to register an account:** `299 characters`
- **Total characters in email after signing in:** `255 characters`

---

### Register an Account with `@dontwannacry.com`

Taking note of the email truncation behavior, we can exploit this logic by registering an account with an email address that is:

- **Longer than 255 characters**
- Ends in our controlled domain
- But when **truncated at 255 characters**, the visible portion ends with:


The email id to be used now is 

```
aaafasighfiyuqabryuawgfibasifnkajsdbgiuafgijaeboifnaijfaokjfiuahfjiahgr90ipqjro89sygfduygsfdtuvdtGUYEDFGWYTDVUYVDuyGDUYucvuavcuyvauyvdfuaycvuayvcuyasvcuyavcuyavcuucauvcuayvclu2o3i1hri97uuc89273r89hiug987niuch89qn397yr89hiu7ay89qah45uiyr0q@dontwannacry.com.exploit-0ab1009903bcf40b8008753f01b300db.exploit-server.net
```
Create an account with the above email-id

![image](https://github.com/user-attachments/assets/ad9866cb-849e-4c43-b3ab-b53cd2591f99)


In the email inbox, click on the link to confirm registration.


![image](https://github.com/user-attachments/assets/90fc7f94-d8dc-46b6-9a10-88e42030b6d0)


Now finally when we log in, we can see that after truncation, our email address ends with **@dontwannacry.com**.


![image](https://github.com/user-attachments/assets/4f5b8d13-9748-43bb-abb2-cb0ea65bedf2)



We can now access the admin panel at */admin*.

![image](https://github.com/user-attachments/assets/02c5c60e-7d7d-4161-af22-e586844e365a)

---

## LAB 7 - Weak isolation on dual-use endpoint


![image](https://github.com/user-attachments/assets/52ab0866-6d46-459a-8494-22a1f085cbe4)



## Solution :

The lab description says that **user's privilege level based on their input.** So by somehow abusing this logic flaw we need to gain admin privileges.

Login as wiener using the credentials provided.
![image](https://github.com/user-attachments/assets/7e4de575-4996-43da-8526-75317265d9fe)


As expected since weiner is a normal user, he is not allowed to access the */admin* panel.

![image](https://github.com/sh3bu/Portswigger_labs/assets/67383098/b2876937-500b-4f4b-91ce-78dfdb199cff)

### Logic flaw in password change functionality -

When we enter current password and old password to change the password of a user, the following POST request is sent to*/my-account/change-password* endpoint.

![image](https://github.com/user-attachments/assets/a7a567bc-f22c-439b-a428-25f32729475b)


So as per this lab's overview, we can try to remove a parameter/remove a parameter and value & see if anything wierd happens.

In the above request to change the password, we can see that the **password change happens for the username that is being provided**.

> This is typically dangerous since  in the password change functionality, if it is dependant on the username then an attacker can try to enter the username as admin & change the password.

#### Removing the  `&current-password=` parameter -

When we remove the **&current-password=** parameter, notice that the server accepts the request and changes the password of wiener.

```
csrf=hDmgDzvRuQsMkrIMeamKQa2NiAjlViHD&username=wiener&new-password-1=1212&new-password-2=1212
```

![image](https://github.com/sh3bu/Portswigger_labs/assets/67383098/49914567-41b8-4df0-8ccb-f486bb7896c8)

### Resetting admin's password -

So this time we use this logic flaw to reset the password of administrator user.

In the form fill the username as **administrator**, and remove the  **&current-password=** parameter.

The POST request now looks like this .

![image](https://github.com/user-attachments/assets/8e37d058-d1a4-4e1f-8a9a-61dcaa80214d)



And we've finally changed/resetted the password of admin user.We can login as admin now using the password we just set.

![image](https://github.com/user-attachments/assets/a5d3f5e7-20f4-4383-9495-9c87fa2fa2d6)


Go to the admin panel & delete the user carlos to solve the lab.

![image](https://github.com/user-attachments/assets/914281ec-b908-42c3-807e-2ad2a2302ce6)

---

## LAB 8 - Insufficient workflow validation

### Lab Description :

![image](https://github.com/user-attachments/assets/483f4623-5112-4520-b325-4a4aa745fccd)


## Solution :

So we need to abuse the flawed workflow while ordering a product to solve this lab.

### Workflow

1. First login as wiener .Click on the leather jacket product & add the item to cart.

![image](https://github.com/user-attachments/assets/6c03c1e4-59f4-4f06-9752-5d9ea876a421)


The following request is sent.

```http
POST /cart HTTP/1.1
Host:aef00b5046c7a4b83d0e156009e00ca. web-security-academy.net
Cookie: session=342CZuircwtnZmoAaSNwDSwpbsUL77uP
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/116.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 36
Origin: https://aef00b5046c7a4b83d0e156009e00ca. web-security-academy.net
Referer: https://aef00b5046c7a4b83d0e156009e00ca. web-security-academy.net/product?productId=1
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Connection: close

productId=1&redir=PRODUCT&quantity=1
```

In the cart page, we can see that the product is added & we can now place the order.

![image](https://github.com/user-attachments/assets/f7aeda72-2134-451d-9e8b-35567229dc00)


2. When we place the order the following POST request is sent to `/cart/checkout`.

```http
POST /cart/checkout HTTP/2
Host: aef00b5046c7a4b83d0e156009e00ca. web-security-academy.net
Cookie: session=FrFZmMsVa1rg3dwRExGgltBTD0gijy4m
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/116.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 37
Origin: https://aef00b5046c7a4b83d0e156009e00ca. web-security-academy.net
Referer: https://aef00b5046c7a4b83d0e156009e00ca. web-security-academy.net/cart
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers

csrf=viHBF1tw4OTvvpMH8ukIZ9TjfivZqcew
```
#### Case 1 - [ product_value > store_credit ]

But then we can't buy the jacket($1337) since we have only $100.

![image](https://github.com/user-attachments/assets/5de9b420-a9ee-4cf4-a575-73e27a3c1c2a)


#### Case 2 - [ product_value < store_credit ]

We repeat the same process again but this time we add a product that costs less than $100.

![image](https://github.com/user-attachments/assets/9a7d99f3-41bc-4c92-a34d-c965489e2bc2)


This time when we place the order, we have another request being sent after */cart/checkout* which is a GET request to */cart/order-confirmation*

![image](https://github.com/user-attachments/assets/6b7ebcba-5332-4099-86f9-88bbda1ed50b)

### Abusing flawed workflow logic -

Thinking from an attacker's perspective, we can add any costly product, in our case the **leather jacket** & just resend the GET request to */cart/order-confirmation* endpoint with parameter `?order-confirmation=true` to place an order wihtout going through the intended workflow.

By this way we're abusing the flawed workflow mechanism since the server doesn't validate the workflow properly.

Now to solve the lab perform the following steps.

- Add the leather jacket to cart (can also add n number of jackets as our wish).
- Send GET request to /cart/order-confirmation.

Refresh the page to confirm that the lab is solved.

![image](https://github.com/sh3bu/Portswigger_labs/assets/67383098/3842b00f-efd5-40ab-9286-57320c73a824)


---

## LAB 9 - Authentication bypass via flawed state machine

### Lab Description :

![image](https://github.com/user-attachments/assets/dfe1e76b-bcef-4b50-a5f2-2aa22bbed8d4)

## Solution :

We need to exploit the flawed workflow validation to login as administrator & delete the user carlos.

Using the **content discovery** tool in burpsuiter, we find that the admin directory is at **/admin**.


1. Enter the given credentials for wiener and login.
   
![image](https://github.com/user-attachments/assets/18bdf20f-802c-4b0a-bd07-d76ddd928e42)

2. The following is the follow-up GET request made to  */role-selector* , which fetches the page to select the role which we want.

```http
GET /role-selector HTTP/2

```

Now we're presented with this page where we can select a role for the user.

![image](https://github.com/user-attachments/assets/0f63e3ab-2543-4c87-8fb3-28927faf7b92)


3.  On selecting a role , the following request is sent.

```http
POST /role-selector HTTP/2

role=user&csrf=wuxcQYkIOd5GkUbiEFaHIKkEAbIakcip
```




### Abusing flawed workflow logic -

Thinking from an attacker's perspective, we can try to just drop the GET request made to */role-selector* and see what role we are assigned by default.

![image](https://github.com/user-attachments/assets/bd8be434-4332-4eac-a855-3fb3ae0bf395)


After dropping that particular request, we now see a link to **Admin panel** at the top right side.

![image](https://github.com/user-attachments/assets/79431b4a-fe47-40c0-acc0-8965b5bf8d60)


> This means that **by default the application assigns administrator privileges to the user unless he specifies any role of his choice!**.

Go to the admin panel and delete the user carlos to solve the lab.

![image](https://github.com/user-attachments/assets/a4a6bd2f-6c0b-4564-b7ec-bb5ef4d81cb3)

---

## LAB 10 - Infinite money logic flaw

### Lab Description :


![image](https://github.com/user-attachments/assets/0d2cbe3a-0d44-4636-9b06-81fbfdbc093d)



## Solution :

Log in as wiener.

When we scroll down all the products in the home page, we can see that there is a signup feature. 

![image](https://github.com/user-attachments/assets/5fef8ae1-2fa9-446f-b939-fcd0d25b57bc)


When we signup, then site gives us a coupon code.

![image](https://github.com/user-attachments/assets/89063ffb-1843-4f89-b683-1cdfd0c65f92)


In the home page, we have a product called gift card. Add it to cart

![image](https://github.com/user-attachments/assets/4e51bd30-e5fe-4f89-b4e3-017e52d67bb3)


Now in the cart section add the coupon *SIGNUP30* to avail discount.

![image](https://github.com/user-attachments/assets/f9224740-e166-4383-87aa-5a62ae31b6cf)

Once we place the order, we get a code to redeem.

![image](https://github.com/user-attachments/assets/79d31afb-ab41-4675-a762-8f1aae733754)


Paste the coupon in the redeem section available at **My-Account** page to redeem some credits .

![image](https://github.com/user-attachments/assets/80092a85-b51b-4906-b724-5c0ddfed5a19)


Now we got extra **$3 dollars** to our store credit.

![image](https://github.com/user-attachments/assets/e208c1f7-81bb-48cc-af3e-937f473b71ad)


### Summary of the steps -

1. Login as wiener .
2. Signup for newsletter to get a discount coupon - **SIGNUP30**.
3. Add **Gift card** product to cart .
4. Apply **SIGNUP30** coupon .
5. Place the order to get a Gift coupon.
6. Redeem the coupon in *My-Account* page to get $3 dollars.

**On repeating this process again and again, we can gain more and more credits which will help us to buy the leet leather jacket.** In order to automate this multi step process, we use *macros* feature in burp.

### Automate the multi step process using macros -

Go to `Project options > "Sessions`.

![image](https://github.com/user-attachments/assets/cef132fd-399c-448a-95f0-102f26873280)

 In the `Session handling rules` panel, click `Add`. The `Session handling rule editor` dialog opens.
In the dialog, go to the `Scope` tab. Under `URL Scope`, select `Include all URLs`.

![image](https://github.com/user-attachments/assets/87185124-76e4-4e94-8648-531e72b3566d)

Go back to the `Details` tab. Under `Rule actions`, click `Add` > `Run a macro`. 

![image](https://github.com/user-attachments/assets/84a31d67-795a-468a-b9ee-890bc6854a47)

Under `Select macro`, click `Add` again to open the Macro Recorder.

![image](https://github.com/user-attachments/assets/cb40e6fb-5583-4bb0-a54d-79f9fcfd43a0)


Select the following sequence of requests: 

```
POST /cart
POST /cart/coupon
POST /cart/checkout
GET /cart/order-confirmation?order-confirmed=true
POST /gift-card
```


![image](https://github.com/user-attachments/assets/3568339e-5d2c-4bdd-a68e-512021a7d47e)

- In the list of requests, select `GET /cart/order-confirmation?order-confirmed=true`. Click `Configure item`. In the dialog that opens, click `Add` to create a custom parameter.

![image](https://github.com/user-attachments/assets/04389bc8-f87f-423b-b1e4-cabda8dd4549)

 Name the parameter `gift-card` and highlight the gift card code at the bottom of the response.

 ![image](https://github.com/user-attachments/assets/19c0bc3c-eb0f-4bae-b1be-7f2625700b42)



- Select the `POST /gift-card` request and click `Configure item` again. In the `Parameter handling` section, use the drop-down menus to specify that the gift-card parameter should be derived from the prior response (response 4). Click `OK`.



![image](https://github.com/user-attachments/assets/8a299b96-e0c4-407e-ab7b-6900e1077d30)

- In the Macro Editor, click `Test macro`. Look at the response to `GET /cart/order-confirmation?order-confirmation=true` and note the gift card code that was generated. Look at the `POST /gift-card request`. Make sure that the gift-card parameter matches and confirm that it received a 302 response. Keep clicking "OK" until you get back to the main Burp window.

![image](https://github.com/user-attachments/assets/22b1c120-7697-47c1-a0b7-8fd2e2f23dab)



- Send the `GET /my-account` request to Burp Intruder. Use the `Sniper` attack type.

- On the "Payloads" tab, select the payload type `Null payloads`. Under "Payload settings", choose to generate **420 payloads**.

Now start the attack. It takes some time to run.

Once completed, we see that we have $1427 credits. 

![image](https://github.com/user-attachments/assets/d38c17f5-4ec8-4645-95fe-4a692f1c69e3)



Now we can buy the leet jacket  & solve the lab.

![image](https://github.com/user-attachments/assets/03ab3abe-c5f4-47be-88c3-b9e4139092b3)

---

## LAB 11 - Authentication bypass via encryption oracle

### Lab Description :

![image](https://github.com/user-attachments/assets/b77916d9-3728-4000-8345-251b5180d398)



### Email Address Parsing Discrepancies

### Complexity of Parsing Email Addresses

Email address parsing is inherently complex due to the diverse ways email addresses can be structured according to RFC standards.

Applications often need to extract domains from email addresses to determine the organization or to apply specific rules, which can lead to inconsistencies if not handled uniformly.

## Exploitation Through Encoding

Attackers can use various encoding techniques to manipulate email addresses in a way that bypasses initial validation but causes discrepancies in parsing logic.

Common techniques include using different forms of encoding (e.g., URL encoding, Unicode) or leveraging rarely used syntax elements in email addresses.

## Impact of Discrepancies

When discrepancies exist, attackers can exploit them to register accounts with email addresses that are technically valid but bypass intended restrictions.

This can lead to unauthorized access to parts of the application meant for specific users or roles, such as admin panels or restricted areas.

## Example Exploits

An attacker might use an email address that appears to belong to a legitimate domain but includes encoded characters or subdomains that are not properly handled by the application.

This could allow the attacker to gain access to features or functionalities they should not be able to use.

---

## Basic Structure

An email address is generally structured as:

```
local-part@domain
```

- `local-part` is the part before the `@`.
- `domain` is the part after the `@`.

---

### Example 1: `"@"@example.com`

**Explanation:**  
Here, the local-part of the email address is `"@"`, which is enclosed in quotes. According to RFC 5322, when the local-part is quoted, special characters such as `@` are considered literal characters within the quotes. Thus, the email address is effectively:

```
@example.com
```

---

### Example 2: `"\"\"\""`@example.com

**Explanation:**  
In this example, the local-part is `"\"\"\""`. To include double quotes within a quoted local-part, each double quote must be escaped with a backslash. Therefore, the local-part is interpreted as a literal string containing escaped double quotes, and the email address is effectively:

```
@example.com

```

![image](https://github.com/user-attachments/assets/017c0c3f-1dd4-4296-b746-9f81c281fbce)


### Comments

- Comments are enclosed in parentheses `()` and can appear anywhere outside of the local-part.
- They are used for annotations and should not affect the interpretation of the address.

**Example:**

(comment)user@(comment)example.com



This is a valid email address.

![image](https://github.com/user-attachments/assets/eb1163c6-deb2-4deb-bd47-7ff551ee0da7)


- Comments can include **spaces** and can be **nested**.

---

### Potential for Confusion

- The combination of **quotes**, **escaping**, and **comments** can indeed be used to create complex and potentially confusing email addresses.
- This can be exploited in scenarios where **email parsers or validators** might not handle these cases consistently.


### Solution :

In the login function, the web application is used **stay logged** into save user cookies.

![image](https://github.com/user-attachments/assets/2e6a1588-8396-4d8c-9b6c-dfa81cf48f23)

A **stay-logged-in** is **base64** cookie and added to the request. However, when decoding, it seems to have been encrypted first.


![image](https://github.com/user-attachments/assets/2472f8c6-5e75-4b81-802f-1a43d73474a1)

On the other hand, each post has a comment function. And when we leave an **a123** invalid email like below:

![image](https://github.com/user-attachments/assets/9b74c5f4-ffcd-4446-b1a6-c279a714d36e)


### Notification Cookie Analysis

The application then reports a line: **Invalid email address: a123**  
and includes a `notification` Base64 cookie.

Decode it and observe that it is also **encrypted**.

We can infer (i.e., **guess**) that:

- The content of the `notification` cookie is the **Base64** of the string  
  **Invalid email address: a123** after being encoded.
- The **encryption algorithm** used for `notification` is the same as used for **stay-logged-in**.



![image](https://github.com/user-attachments/assets/5b02fad9-1e3f-4465-a4d7-5c55c589b850)

With a value `“a”` in this notification cookie cookie we generate an internal server error:

![image](https://github.com/user-attachments/assets/3eebc2ac-48f7-4469-b38c-1b94de941abb)


With a base64-encoded value **“YQ==”** we see information about the encryption. It looks it uses padded cipher and blocks of 16 bytes, so it could be **AES-128**:


![image](https://github.com/user-attachments/assets/0c4b8eaa-7ab5-4d15-b54b-a516e5e2b6dc)



We will verify by taking the value **stay-logged-in** of **nofitication**.

![image](https://github.com/user-attachments/assets/e369bbf5-d2cf-4db8-bcba-0831b7a5ae5b)


The results show that the content of **stay-logged-in** is **username:timestamp**.


![image](https://github.com/user-attachments/assets/d0247fd1-8354-48f7-b3f8-63f9d59349b0)


Now, we need to create a value **stay-logged-in** for **administrator** or based on the encoding of the field notification. And since notificationit is created through the field email, we will pass the payload at **email**. We will pass it **administrator:<timestamp>** at email.

![image](https://github.com/user-attachments/assets/58fedd1d-c9cd-4d78-a795-de6d63dbc2d3)


The message can be seen **Invalid email address: administrator:1672593998338** with notification its base64 encoded form value of **administrator:1672593998338**. To do that, take the notification current value, decode the URL+base64 and remove the first 23 bytes.


**Info:**


![image](https://github.com/user-attachments/assets/bd091ae8-0979-40a3-b949-e8cd76ba4552)



![image](https://github.com/user-attachments/assets/7f60f3fc-c349-430f-9d38-f811176590c5)

![image](https://github.com/user-attachments/assets/61ab30a1-272c-43b4-aa3b-51ad8ddc4df9)



After deleting the above **23 bytes**, perform base64 encoding + URL encoding to pass into the cookie notification to see if it has been cut successfully: **O3tEa1GHAnSumMNJYUyeNZmLguHpQlzLaC+N7hZEpoujFylp6tXe1Fc%3d**. The result of the ciphertext message in notification must be a multiple of **16**. I can guess the encryption algorithm for each block of 16 bytes.


![image](https://github.com/user-attachments/assets/8e0664e3-950d-4edd-b85c-52b7b014629f)


So I need to insert any 9 bytes first to combine with the above 23 bytes into **32 bytes** to delete.


![image](https://github.com/user-attachments/assets/0fc7e09c-a5c7-4fa5-84ea-bf7fe476ddcd)


Knowing it uses 16-bytes blocks and there is a prefix of 23 characters ("Invalid email address: “), we will add 9 characters of ”padding" in that second ciphered block:

![image](https://github.com/user-attachments/assets/98bed342-1d28-45a1-943e-db705edc5970)


We will take the encrypted value, URL-decode and base64-decode it, and delete the first 2 16-bytes blocks:

```
bRmw%2bImnDFvvwECQSiG1J8dfoUcrqKgkyQfr8wfI1J9bRCG%2bSLS06HPtXsMPhzuBQTkxD8oSxM2l3LhRCdZ3IQ%3d%3d
bRmw+ImnDFvvwECQSiG1J8dfoUcrqKgkyQfr8wfI1J9bRCG+SLS06HPtXsMPhzuBQTkxD8oSxM2l3LhRCdZ3IQ==
...
W0Qhvki0tOhz7V7DD4c7gUE5MQ/KEsTNpdy4UQnWdyE=
W0Qhvki0tOhz7V7DD4c7gUE5MQ/KEsTNpdy4UQnWdyE%3d

```
![image](https://github.com/user-attachments/assets/60ac80ba-1193-47bd-8193-e693d23e9c26)


First we will set the value **“W0Qhvki0tOhz7V7DD4c7gUE5MQ/KEsTNpdy4UQnWdyE%3d”** for the **“notification”** cookie to check it is decrypted correctly:

![image](https://github.com/user-attachments/assets/e8ea2eb7-78dd-4ee9-8a03-2aaabcafb1fe)



We can delete the "session" cookie and use this value to log in:

```

GET /my-account?id=administrator HTTP/2
...
Cookie: stay-logged-in=W0Qhvki0tOhz7V7DD4c7gUE5MQ%2fKEsTNpdy4UQnWdyE%3d
…
```

![image](https://github.com/user-attachments/assets/1243273b-4015-4326-8481-64c09a743d63)


And then delete the user and lab is solved:

![image](https://github.com/user-attachments/assets/3aa8cea6-ec79-4e0a-8834-ca6e0537b340)




