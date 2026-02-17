## Labs Covered

This write-up focuses on the following **APPRENTICE-level labs** from the PortSwigger Web Security Academy:

**1 Unprotected admin functionality**  
<blockquote>
  This lab demonstrates how administrative functionality can be exposed without proper access controls, allowing unauthorized users to access sensitive areas of the application.
</blockquote>


**2 Unprotected admin functionality with unpredictable URL**  
<blockquote>
  This lab highlights how security through obscurity (using unpredictable URLs) is insufficient if proper authentication and authorization controls are not enforced.
</blockquote>


 **3 User role controlled by request parameter**  
 <blockquote>
  This lab illustrates how manipulating request parameters that control user roles can lead to privilege escalation and unauthorized access.
 </blockquote>


 **4 User role can be modified in user profile**  
 <blockquote>
  This lab shows how insecure user profile management can allow users to modify their own roles, potentially gaining administrative privileges.
 </blockquote>


**5 User ID controlled by request parameter**  
<blockquote>
  This lab demonstrates insecure direct object reference (IDOR) vulnerabilities where user identifiers in requests can be manipulated to access other users’ data.
</blockquote>

**6 User ID controlled by request parameter, with unpredictable user IDs**  
<blockquote>
  This lab extends the IDOR concept by introducing non-sequential, unpredictable user IDs that still lack proper authorization checks.
</blockquote>


**7 User ID controlled by request parameter with data leakage in redirect**  
<blockquote>
This lab shows how sensitive information can be leaked via redirects when user input is not properly validated or sanitized.
</blockquote>

**8 User ID controlled by request parameter with password disclosure**  
<blockquote>
This lab demonstrates how manipulating request parameters can lead to exposure of password information for other users.
</blockquote>

**9 Insecure direct object references**  
<blockquote>
  This lab emphasizes the importance of implementing proper access controls to prevent unauthorized access to internal resources based on user-supplied object references.
</blockquote>


---
## LAB 1 - Unprotected admin functionality

## Lab Description :

![image](https://github.com/user-attachments/assets/58dca2cf-1524-4431-a4bf-70883fdfd46c)



---

## Solution :

When the lab loads, a standard shopping website interface is displayed. Selecting the `My Account` option redirects the user to the `/login endpoint`, indicating that authentication is required to access this section.

![image](https://github.com/user-attachments/assets/8e8f962e-e555-4c01-9744-620d03cfcf62)

The next objective is to bypass the login page and gain direct access to the admin interface. To achieve this, we can investigate commonly exposed web directories, such as `robots.txt` and `sitemap.xml`, which may disclose hidden or sensitive endpoints.

 
#### robots.txt

![image](https://github.com/user-attachments/assets/96ad114c-7140-4261-93bf-b9a40018641d)

We see a **disallowed login** entry here for the admin panel which is `/administrator-panel`.

On visiting the `/administrator-panel` directory, we get the admin panel.

![image](https://github.com/user-attachments/assets/78530bd7-64c3-4a28-9beb-97c603a62abd)


So we click the link to delete the user *carlos* to solve the lab. 

![image](https://github.com/user-attachments/assets/9fec70b4-34eb-4d33-8ffd-3fc60d554f3c)

---
## LAB 2 - Unprotected admin functionality with unpredictable UR

## Lab Description :

![image](https://github.com/user-attachments/assets/8e7e4395-a21b-4eeb-98c8-3870f877643c)

## Solution :

The lab webpage looks like this,

![image](https://github.com/user-attachments/assets/4023f352-466a-44b0-8c70-b6a4cadb994e)


Clicking on `My Account`, takes us to the *Login page* at `/login`.

![image](https://github.com/user-attachments/assets/4d39ac27-a578-4971-aafb-8bb0458f6021)

By clicking Control+u we can read the source code and find the admin panel.

![image](https://github.com/user-attachments/assets/b34f388d-eba3-4931-9560-f0d2a52239c1)

So we could directly browse to that directory to view the admin panel.

![image](https://github.com/user-attachments/assets/61afc316-2c74-4dd4-a52a-1c1410b21530)

Click on ther  *DELETE* link of carlos to delete the carlos user .Thus lab is solved.

![image](https://github.com/user-attachments/assets/5a3c86cb-1f22-42e9-b02f-c8e22de78a11)

___

## LAB 3 - User role controlled by request parameter

## Lab Description :

![image](https://github.com/user-attachments/assets/9fcd4525-4ec6-4ea1-98a6-02dbf5b0a8b9)



## Solution :

Some applications determine the user's access rights or role at login, and then store this information in a user-controllable location, such as a **hidden field**, **cookie**, or preset query string parameter. The application makes subsequent access control decisions based on the submitted value. For example:

- https://insecure-website.com/login/home.jsp?admin=true
- https://insecure-website.com/login/home.jsp?role=1

This approach is fundamentally insecure because a user can simply modify the value and gain access to functionality to which they are not authorized, such as administrative functions.

### Steps -

We have our login page,

![image](https://github.com/user-attachments/assets/732a0b50-42c6-418d-8435-707d514cd642)



In the lab description , it is given that the admin page is at `/admin`. Lets try visiting that page.

![image](https://github.com/user-attachments/assets/ceba5dfb-80b1-4a19-8a3f-fdb914b63887)


It says we can view only if we are admin!

We have a login credential `wiener:peter` .Lets try logging in and see what requests & responses being made.

Once we hit login after entering username and password, it sends a *POST* request like this,

![image](https://github.com/user-attachments/assets/04ad54b5-ba77-4903-852b-1d22d37177ca)


Then a *GET* request is made to retreive the `/myaccount` page .

![image](https://github.com/user-attachments/assets/e9913c2a-c522-42f9-8ea8-222ce9f98c7b)


Here we have an interesting cookie - `Admin=false`.

The reponse looks like this ,

![image](https://github.com/user-attachments/assets/8cf54e74-212b-44f8-afee-d329b95ced67)


We are logged in as *wiener* 


![image](https://github.com/user-attachments/assets/90c04642-b70d-416c-b91a-31a1c7b6b9c1)



## What happens if we change the cookie value to `Admin=true` ?

We modify all the requests where the cookie is set to `Admin=false` to Admin=true`

#### POST req to /login endpoint

![image](https://github.com/user-attachments/assets/5c945c5b-5be0-4896-bc11-af75812edb70)


#### GET req to /myaccount endpoint

![image](https://github.com/user-attachments/assets/562b3b1d-2e2e-4b9f-9338-902821a01a43)

#### GET req to /admin endpoint

After getting the myaccount page, we click the `Admin panel` link, the request sent is modified as follows

![image](https://github.com/user-attachments/assets/111d5f48-b8c7-4f38-9813-3b308bea51e8)


Atlast, we get the admin panel .

![image](https://github.com/user-attachments/assets/4fd5bce7-8bba-4969-b966-a139c2076fbe)


Now we can delete the suer carlos and solve the lab.

#### GET req to /admin/delete endpoint

Capture the request to delete the user carlos & change the cookie value here too!

![image](https://github.com/user-attachments/assets/8d452a42-37d7-4d98-b49c-ec91aaa1c899)

We have sucessfully solved the lab.

![image](https://github.com/user-attachments/assets/4fe2094d-bd33-4a35-9410-c089e7ec92e7)


---
## LAB 4 - User role can be modified in user profile


## Lab Description :

![image](https://github.com/user-attachments/assets/f636db0c-f822-4af1-ad1d-7cd6fb7e6dcc)



## Solution :

So as per the lab description, we can view the admin panel only if our `roleID=2`.


Login page -

![image](https://github.com/sh3bu/Portswigger_labs/assets/67383098/35fc29d1-5d2f-4544-a7cc-98ce5fb2e27b)

Enter the credentials which are given for testing which is `wiener:peter`& click *LOGIN* button, 

![image](https://github.com/user-attachments/assets/58e743fa-4c5d-4376-88d1-b0c658c929c4)


Noticed the ‘My account’ section and observed the update email feature.

![image](https://github.com/sh3bu/Portswigger_labs/assets/67383098/04910894-9e36-4e42-94fd-ec7690d3f960)


*Till now we didn't see any suspicious cookie values being sent from our client*

Lets move on & try to update our email.

![image](https://github.com/user-attachments/assets/1973afc5-1fa6-4999-ac96-911b0294f0aa)


**Request** :

![image](https://github.com/user-attachments/assets/64d191f5-6275-493e-853c-896ab991201f)


Send the request to repeater (I tried sending all the previous requests to repeater, it didn't have the *roleid* cookie either in request or response)

**Response** :

![image](https://github.com/user-attachments/assets/22542984-1f8e-40b6-8395-6944f86f6f14)


Observe that we have a **roleid=1** in the JSON response.

So add the value `roleid=2` in the JSON request & see what is the response in browser

![image](https://github.com/user-attachments/assets/590cd5d8-93be-4e98-b2f9-e184ea325ddb)

![image](https://github.com/user-attachments/assets/3d1c3c69-0141-4a12-90ee-56c0e5a92883)



**We have a 302 redirect**

![image](https://github.com/user-attachments/assets/693675ec-406a-4ea6-a2f5-8a4006f3a8ac)



Click `Follow redirect`,

Now we can see the link to **Admin Panel** in the browser.

![image](https://github.com/user-attachments/assets/e572c70e-5df7-4586-b7c0-28fbe65e12d2)


Now click on admin panel & delete the carlos user to solve the lab.

![image](https://github.com/sh3bu/Portswigger_labs/assets/67383098/448da80e-2713-41e1-bba1-3e7864f50bed)

---
## LAB 5 - User ID controlled by request parameter

## Lab Description :

![image](https://github.com/user-attachments/assets/6d36d0bb-6cf3-4ad5-8dbe-96b2baea47f9)


## Solution :

When ther lab loads , we see the usual shopping website. Clicking on `My account` takes us to a login page.

![image](https://github.com/user-attachments/assets/f0d94399-4473-4f9d-a11c-446a16acf45f)


We enter the credentials which is given in the lab description - `wiener:peter`

When we login we get to see the API key of wiener - `T9VQGi3yf81cho2IzdP5jN61hT9zc1YA`

![image](https://github.com/user-attachments/assets/db527358-2f0b-440f-a991-a908681c2dbb)


To solve the lab , we need to retreive the API key of carlos user.

When we click on `My Account` after loggin in as wiener, a request is sent like this

![image](https://github.com/user-attachments/assets/a5843779-5bbc-4b5c-884d-9c39bf0a9254)


It contains `?id=wiener` parameter.

Change the value to `?id=carlos`, we get the API key of carlos and thus solved the lab

![image](https://github.com/user-attachments/assets/fe57bec5-b48a-4b36-b609-35beea03813a)


![image](https://github.com/user-attachments/assets/a0562142-1471-4b40-8ec3-b1f7da149ef1)


---
## LAB 6 - User ID controlled by request parameter, with unpredictable user IDs

## Lab Description :

![image](https://github.com/user-attachments/assets/7855cb01-d24b-488b-b29d-04ff97b4b3f3)



## Solution :

In some applications, the exploitable parameter does not have a predictable value. For example, instead of an incrementing number, an application might use **globally unique identifiers (GUIDs)** to identify users. Here, an attacker might be unable to guess or predict the identifier for another user. However, the **GUIDs belonging to other users might be disclosed elsewhere in the application where users are referenced, such as user messages or reviews.**

Click on `My Account` , it takes us to login page. Use the credentials `wiener:peter` to login.

![image](https://github.com/user-attachments/assets/6b7b28cc-fc09-46f6-acb0-6340e5756020)


Once we login, we can see the API key of wiener.

Click on `My Account` & capture the request.

We have the **GUID** of wiener in the request. We need to somehow find the GUID of carlos to get his API key.

For that , click on the home page and browse through all the blog posts by carlos, Click on his username

![image](https://github.com/user-attachments/assets/a10bb669-201c-430c-8e5d-d744d93ff69c)


Now we got the GUID of carlos - `0cae1b22-401e-46b4-b767-09e89441403a`


GUID of wiener - `jrrAYctrKLzzPUvGA7eKyh9NmlO6SPzm`
GUID of carlos - `0cae1b22-401e-46b4-b767-09e89441403a`

Now in the `My Account` page , click on the link , capture the request and modify the GUID of wiener with carlos to get the API key.

![image](https://github.com/user-attachments/assets/7decfdee-ba0a-45eb-bc08-000d1249d248)


In the response  now we get the API key of carlos - `9FLbgOm1kRjJoisnIuYN51HHtQdtOwYZ`

![image](https://github.com/user-attachments/assets/549a4126-8488-4bc0-85e3-dd70e3068bca)


Thus we solved the lab.

![image](https://github.com/user-attachments/assets/0189e6bf-6cbc-4d29-928f-0aae9ac8ba27)

---

## LAB 7 - User ID controlled by request parameter with data leakage in redirect

## Lab Description :

![image](https://github.com/user-attachments/assets/f521124a-ff87-4475-b2f2-04a36b5542fa)


## Solution :

In some cases, an application does detect when the **user is not permitted to access the resource**, and **returns a redirect to the login page**. However, the r**esponse containing the redirect might still include some sensitive data belonging to the targeted user**, so the attack is still successful.

Clicking on `My Account` takes us to the login page where we can login as wiener useing the credentials `wiener:peter`.

We get the account page which displays wiener's API key - `C9CMxZRxQVICJFNdYKDPrmiKSY5NxbMG`

![image](https://github.com/user-attachments/assets/75c8694c-ae96-4e03-903b-9838e3c968aa)

When we click on `My account` again, the browser sends a request which contains `?id=wiener`

```http
GET /my-account?id=wiener HTTP/2
Host: redacted
Cookie: session=Ues4LJi6ijUdDxBu151S7lxWUznAJ8SH
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:106.0) Gecko/20100101 Firefox/106.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: redacted/my-account
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
```

Send the request to repeater tab. Change the value to `?id=carlos` and observe the response.

![image](https://github.com/user-attachments/assets/67693f7c-ba73-4cc4-a294-b0bf3438bbc4)

We get a `302 Redirect` response back .

```http
HTTP/2 302 Found
Location: /login
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
X-Frame-Options: SAMEORIGIN
Content-Length: 3395
```

Here the **API key of Carlos is leaked in the redirect response**.

![image](https://github.com/user-attachments/assets/dad5feb6-2821-401f-ac65-ad8d70b694b7)

API key of wiener - `C9CMxZRxQVICJFNdYKDPrmiKSY5NxbMG`
API key of carlos - `M8XFUdMj MOWODYF4vovFWYLGzbot2KVX`


Submit the key and the lab is solved.

![image](https://github.com/user-attachments/assets/751bee95-5ca4-4cd6-aed6-72cba77b98d4)

---

## LAB 8 - User ID controlled by request parameter with password disclosure


## Lab Description :

![image](https://github.com/user-attachments/assets/4e8b67d1-d518-44bf-a4a7-9865715aff7d)


## Solution :

The account page that contains the current user's existing password, prefilled in a masked input. So lets login as wiener to see what the account page has.

![image](https://github.com/user-attachments/assets/5ba758b6-fb8c-4572-8403-8ccc25f93a35)

We can see there is a **pre filled password** in the password field. We can't see the password in plaintext but we can try reloading the page / view source-code to see what the password is.

![image](https://github.com/user-attachments/assets/aa809bc1-e504-4700-8624-f1317aa9d79e)

So the password is prefilled with the password of the user winer which we logged in.

Now if we click on the `My account` link again after logging in , the page reloads where it sends a request as below.

![image](https://github.com/user-attachments/assets/9be2727a-80ab-49ce-8abd-1b4490d96869)


Change the parameter `?id=wiener` to `?id=administrator`.

![image](https://github.com/user-attachments/assets/cb414daa-6047-4b81-9fd0-bbcfe2185e4d)


![image](https://github.com/user-attachments/assets/d091f807-6948-435e-8363-f6b6c5af8665)



Thus we have sucessfully exploited it as it leaked the admin's password in the response.

![image](https://github.com/user-attachments/assets/10ef1496-c0d5-4a72-92b4-9104bc98ceae)


Password - `nrmwf5x1228f0spbcvxt`


Now we can login as admin & delete user carlos to solve the lab.

![image](https://github.com/user-attachments/assets/77520b65-855b-4ff7-92bc-c0fd54e452dd)



---

## LAB 9 - Isecure direct object references

## Lab Description :

![image](https://github.com/user-attachments/assets/16318b42-a482-434e-82bf-9c6d83772920)



## Solution :

![image](https://github.com/user-attachments/assets/db4c6453-1ce3-4b61-aed2-c6bca4d5624d)


The lab page contains a `Live chat` link which allows us to send messages and also view transcripts,

![image](https://github.com/user-attachments/assets/28cfac99-43b8-4613-9c0d-416d957efb94)


For testing, first I tried to send a message.

![image](https://github.com/user-attachments/assets/d546d452-df90-49f7-bb9a-06821229f807)


Now when I click `transcript`, it disconnects from the chat and downloads the chat transcript.

![image](https://github.com/user-attachments/assets/44ba6604-82a1-433b-b3ed-db840e178054)


Notice that **The transcript downloaded was 2.txt and why not 1.txt?.  Maybe there was previous chats which contains  carlos's password**


As we guessed, the first chat **1.txt** contains the chat which has carlos's password.

![image](https://github.com/user-attachments/assets/f430a2af-51a8-4da6-a739-9cf5510630ab)


Now login as carlos, to solve the lab.

![image](https://github.com/user-attachments/assets/87c55d49-0e5e-46a8-b0fd-c1aa9abc15b6)

---






















































































