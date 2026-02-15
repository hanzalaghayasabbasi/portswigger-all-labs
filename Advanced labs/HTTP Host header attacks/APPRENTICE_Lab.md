## Labs Covered

This write-up focuses on the following **APPRENTICE-level labs** from the PortSwigger Web Security Academy related to **HTTP Host Header Attacks**:

**1 Basic password reset poisoning**  
<blockquote>
This lab demonstrates how attackers can exploit unsanitized Host headers to poison password reset links sent to users.
</blockquote>

**2 Host header authentication bypass**  
<blockquote>
This lab shows how manipulating the Host header can be used to bypass access controls or authentication checks.
</blockquote>

---

### LAB 1 - Basic password reset poisoning

### Lab Description

<img width="916" height="367" alt="image" src="https://github.com/user-attachments/assets/634d1594-dd09-4433-b110-d4ca64f73a73" />

### Solution

First we can see below our exploit sever have email client and access log for looking request come to it

<img width="895" height="509" alt="image" src="https://github.com/user-attachments/assets/5f3efe1b-a5c8-4f33-8b5e-8859054f81ed" />

Login as `wiener:peter`


<img width="1716" height="698" alt="image" src="https://github.com/user-attachments/assets/a7a56be2-3754-45f6-ad0f-571415cad16c" />


Now we click on forget Password

<img width="1075" height="631" alt="image" src="https://github.com/user-attachments/assets/0779104a-5dbe-4381-9bbe-58a9427ccfd9" />



The above forget Password will redirect us to enter name or email which we want to change Password. I enter **wiener** which I want change Password

<img width="1766" height="394" alt="image" src="https://github.com/user-attachments/assets/817447f5-d2c0-46a0-b384-d98205386e8c" />



So when I submit wiener and  goto email, I can see that that  that a forger link to change Password which contain
Token And also wiener email which is `winer@exploit…………… ` which backend has send Password change to user


<img width="948" height="203" alt="image" src="https://github.com/user-attachments/assets/91799e12-ae66-457f-9bb3-a533656575c2" />



Click on above change Password link and Now we can change Password

<img width="934" height="425" alt="image" src="https://github.com/user-attachments/assets/ae35f77f-dcda-40f5-9959-a6075b22238e" />


				

Now I have click on forgetPassword and  Intercept it to burp


<img width="1917" height="624" alt="image" src="https://github.com/user-attachments/assets/82b83319-db1c-41d9-aad6-218d9d08d592" />


Now send to Reapeter above request to chang host-header to send change Password functionality to attacker site


<img width="1852" height="823" alt="image" src="https://github.com/user-attachments/assets/b4896fc5-c0ea-40a4-8733-21f0d054acd7" />



Now our weiner email is `winer@exploit-0aa……………….` ,So we have a site which look for request given to exploit-0aa……… website we can also say that it's attacker website looking for request,Now we change host header  website To user `controlable website`  and  username to carlos which  will give get request to attacker website and have token of  carlos which we have to change Password

<img width="1312" height="531" alt="image" src="https://github.com/user-attachments/assets/0fe440bc-d0ae-4a9c-908f-0500beda37ba" />



Now we send above request and we can see that in access log we have get request to our website which contain token of user in our case it was carlos which we want to change Password to solve lab

<img width="1908" height="283" alt="image" src="https://github.com/user-attachments/assets/0d556a52-df09-4b9a-bb84-b3fea7e29d63" />



Now we  have look above how do change wiener password  and ,Now we copy above url of get which containg carlos token
And paste in browser and change Password of carlos

<img width="1556" height="686" alt="image" src="https://github.com/user-attachments/assets/d83d6343-8e6e-40ff-a36f-2371f4d3bc35" />


Submit above request and   change pasword and  login as carlos and lab is solved


<img width="1661" height="658" alt="image" src="https://github.com/user-attachments/assets/e6202927-33a7-4f70-8cc2-10a5b7d0d899" />

<img width="1231" height="205" alt="image" src="https://github.com/user-attachments/assets/0920408a-3a47-4554-a603-4c8b774efd3a" />

---

### LAB 2 - Host header authentication bypass

### Lab Description

<img width="919" height="277" alt="image" src="https://github.com/user-attachments/assets/33032ed0-71e8-4974-8031-24993eb2f490" />

### Solution

Looking at admin panel we can see that we have admin page

<img width="1057" height="268" alt="image" src="https://github.com/user-attachments/assets/2a6aa053-ce80-46f7-8f3d-6b90c6fa9fc7" />


Navigating to that tell us that only local user can access it

<img width="1714" height="458" alt="image" src="https://github.com/user-attachments/assets/d08f44d9-4293-47fa-b306-88b284b3dc9a" />


Intercepting the above admin request through burp


<img width="1776" height="694" alt="image" src="https://github.com/user-attachments/assets/d080e426-8fde-4932-aa49-12f13ee2e71f" />

Changing host url to `localip 127.0.0.1` but it did not work

<img width="1781" height="655" alt="image" src="https://github.com/user-attachments/assets/d7f35f4f-bedb-431a-8f78-91353a3ec1a2" />


Now changing to localhost to our `host header`  gives us `admin panel`

<img width="1755" height="670" alt="image" src="https://github.com/user-attachments/assets/d395626d-160b-4d45-b946-3319420dbb30" />


To solve lab we have to delete carlos,So  deleting carlos to solved tha lab.

<img width="1375" height="540" alt="image" src="https://github.com/user-attachments/assets/8e044ca8-10bb-4e34-b36e-dd83c7cfc14d" />


And lab is solved

<img width="1585" height="385" alt="image" src="https://github.com/user-attachments/assets/fba65774-49d2-432c-a83e-d040d1383032" />


---


