## Labs Covered

This write-up focuses on the following **APPRENTICE-level labs** from the PortSwigger Web Security Academy:

**1 Detecting NoSQL injection**  
 <blockquote>
  This lab demonstrates how attackers can identify NoSQL injection vulnerabilities by sending crafted input that modifies the database query behavior.
 </blockquote>

  **2 Exploiting NoSQL operator injection to bypass authentication**  
  <blockquote>
  This lab shows how attackers can use NoSQL injection to manipulate query logic and bypass authentication, gaining unauthorized access to accounts.
  </blockquote>

---

## LAB 1 - Detecting NoSQL injection

### Lab Description :

![image](https://github.com/user-attachments/assets/73ae0211-8927-4980-a775-010e8d49529f)


### Solution :

In this test, we attempt to identify whether the application is vulnerable to NoSQL injection by submitting a special character and observing the response behavior.



In **Burp Suite Repeater**, modify the request by inserting a **single quote (`'`)** into the `category` parameter:

✅ **URL-encoded version:**

```
category=%27
````
![image](https://github.com/user-attachments/assets/44658c64-807d-4cea-b3e5-6dab8856183f)


Now I enter a valid JavaScript payload, URL-encoded `'+'` as `%27%2B%27`. Notice that it doesn't cause a syntax error.  
This indicates that a form of server-side injection may be occurring.

![image](https://github.com/user-attachments/assets/4357749d-b241-40da-b1ef-8acfe29175bb)


Now we have identified that the input is vulnerable by inserting different conditions.  
Next, I entered `' && 0 && 'x`, which caused an error and did not display unreleased products because we used an **AND** condition that evaluates to false.  
The URL-encoded payload is: `%27%20%26%26%200%20%26%26%20%27x`

![image](https://github.com/user-attachments/assets/0825c4ed-e3f6-43dc-8d7c-219055d71735)


Then I entered `' && 1 && 'x`, which caused no error because the condition evaluates to true.  
This confirms that the input is being interpreted in the server-side logic.  
The URL-encoded payload is: `%27%20%26%26%201%20%26%26%20%27x`

![image](https://github.com/user-attachments/assets/800bcd10-0292-46dd-8d06-4887fb81c4bf)


I used the OR-based payload `' || 1 || '`, which evaluates to true and displays the unreleased products.  
This confirms that the input is being interpreted on the server side and a NoSQL injection vulnerability exists.  
The URL-encoded payload is: `%27%20%7C%7C%201%20%7C%7C%20%27`

![image](https://github.com/user-attachments/assets/a5f7150d-69b8-4b1d-a3a4-0f064539580f)


## LAB 2 - Exploiting NoSQL operator injection to bypass authentication

### Lab Description :

![image](https://github.com/user-attachments/assets/0dbd316e-7640-4483-9dc6-a5a06d4fb2f7)


### Solution :

First, I logged in using the credentials **wiener** and **peter**, and intercepted the request using **Burp Suite**.

![image](https://github.com/user-attachments/assets/8694fcee-4497-437b-8257-163365e91e07)

Below is the intercepted request in Burp Suite:

![image](https://github.com/user-attachments/assets/59b20d4d-39de-4e7a-a93b-c27bcbcfa655)

````markdown
This is a login page that does not use any redirection link after form submission.  
Therefore, we used **Operator Injection** instead of **Syntax Injection**.

The payload used is:  
```json
{"username":{"$regex":"wie.*"},"password":{"$ne":""}}

```
````

Since we already know the credentials (`wiener` / `peter`), we attempt operator injection to verify the vulnerability.
As observed, the request is successfully processed, and we are redirected — confirming that operator injection is working.

![image](https://github.com/user-attachments/assets/b4ded506-3bab-4e37-9945-fd1c9eba05a0)

Now we have to log in as **admin** to solve this lab.  
Using the same logic as above, we modify the payload to target the admin account.  
We observe that the response redirects us to the admin panel, confirming successful login.  
Finally, we open the same request in the original browser session — and the lab is solved.

![image](https://github.com/user-attachments/assets/396cd115-7c24-4fba-ba1d-34c4e3b6176b)

Solved the lab by performing NoSQL injection to bypass authentication and access the admin account.  

This allowed entry to the admin panel, confirming the vulnerability and completing the challenge successfully.


![image](https://github.com/user-attachments/assets/fe5fecf9-4048-4619-b461-2586fdeba400)




