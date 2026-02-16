## Labs Covered

This write-up focuses on the following **PRACTITIONER-level labs** from the PortSwigger Web Security Academy:

**3 Exploiting NoSQL injection to extract data**  
   <blockquote>
  This lab demonstrates how attackers can use NoSQL injection to enumerate and extract sensitive data directly from the database by manipulating query parameters.
   </blockquote>

  **4 Exploiting NoSQL operator injection to extract unknown fields**  
 <blockquote>
  This lab shows how attackers can use NoSQL operator injection to extract information from fields that are not displayed to the user by leveraging injection payloads to return hidden fields.
 </blockquote>

---

## LAB 3 - Exploiting NoSQL injection to extract data

### Lab Description :

![image](https://github.com/user-attachments/assets/38fc853e-ff26-4f65-96be-35342fa2ef22)


### Solution :

When I intercepted the request using **Burp Suite**, I observed a `GET` request to the following endpoint:

```

/user/lookup?user=wiener
```

I then sent this request to the **Repeater** tab for further testing and manipulation.


![image](https://github.com/user-attachments/assets/dcdfc27e-35d6-43a7-b13b-b1a4aa75db8f)


I opened the request in the original browser session and modified the parameter using a single quote `'` in URL-encoded form `%27`.

This resulted in the following error message:



There was an error getting user details


This indicates that the input was not properly sanitized and caused a syntax error, suggesting a potential injection point.

![image](https://github.com/user-attachments/assets/afb71abf-1baa-4b53-8a5d-96de204cdc02)

I used the payload `'+'`, which I URL-encoded as `%27%2B%27`, before injecting it into the parameter.

If we do not encode it properly, the application does not return the expected result.  
Using the URL-encoded version ensures the payload is processed correctly by the server.

![image](https://github.com/user-attachments/assets/12a01c6c-66cf-4ed0-9844-52b2fe2666a8)


Then I used the payload `' && '1'=='2` to test for a false condition.  
The application responded with:

```

Could not find user

```

This indicates that the condition was evaluated and returned false, confirming that server-side logic is being affected by our injection.

![image](https://github.com/user-attachments/assets/103ace73-67b9-4660-aba8-bccd153a1c9d)

Then I used the payload `' && '1'=='1`, which is a condition that always evaluates to true.

The application responded without an error, confirming that the injected condition was successfully interpreted and the logic was executed as expected.

![image](https://github.com/user-attachments/assets/4d513300-9973-47ed-bd49-e6c610225467)

Which is giving us valid result which mean this payload will work

![image](https://github.com/user-attachments/assets/e831c8b2-b573-4e40-9617-f65fc6771c55)


Now, our goal is to retrieve the **administrator** user's data.

To do this, I modified the input to target the `administrator` account while maintaining a condition that always evaluates to true:

```

administrator' && '1'=='1

```

This allows the application to process the request without an error and return the administrator’s information.

![image](https://github.com/user-attachments/assets/0648b86c-2eb5-44bc-b463-e49a8c76ab7e)


Then I used the following payload to determine the password length of the **administrator** account:

```

administrator' && this.password.length < 30 || 'a'=='b

```

This payload checks if the password length is less than 30.  
If the response returns successfully, it confirms that the condition is true — helping us estimate the length of the password.

![image](https://github.com/user-attachments/assets/4d6131a4-04d3-4137-91e1-8f6ebd6df973)



### Finding the length of password :

To find the length of the password , we can use the following query
```sql
?user=administrator' && this.password.length < 30 || 'a'=='b
```

> We can stop at *<30* but since the query has a *'* at the end, we provide the *OR* query ie(** || 'a'=='a**).
> Note that we don't end the equal statement with a `'` because there is a trailing `'` at the end of the query getting added automatically at the end.

The response shows the email of admin. It means the query is executed successfully & confirming that **the password length is less than 30.**

![image](https://github.com/user-attachments/assets/da66734d-59be-4428-9001-fc713084c792)

When we provide `this.password.length < 6`, the query fails & we get a failed response (*"message": "Could not find user"*).

![image](https://github.com/user-attachments/assets/86dbdb80-cfc0-4205-81ef-671799bad21f)
![image](https://github.com/user-attachments/assets/ea493ec3-c077-4782-a481-8e8b9b7643d1)

So **the length of admin's password is 8**.

![image](https://github.com/user-attachments/assets/92978b1c-b065-4de6-9386-6927bcc8499e)


After sending the above payload, we successfully received a response containing the **administrator** details.  
This confirms that the condition evaluated to true.

So now, we proceed to find the **exact length** of the administrator’s password by adjusting the payload to test different lengths using the `.length` property in our injection.


![image](https://github.com/user-attachments/assets/d5441766-37ec-41e7-ac11-3aff9bf563b4)


### Finding admin's password -

Now we ned to bruteforce each position from **0-7** by bruteforcing it with **a-z** to find the password.

Modify the nosql query payload as follows.### Finding admin's password -

Now we ned to bruteforce each position from **0-7** by bruteforcing it with **a-z** to find the password.

Modify the nosql query payload as follows.

![image](https://github.com/user-attachments/assets/c973165b-7bd3-464b-81d4-8613b7004963)

Send the request to Intruder tab, Add the `this.password[**$0$**]` as payload 1 and `this.password[$0$]='**$a$**` as paylaod 2.

Payload 1 - Numbers from 1-10
Payload 2 - Characters from a-z

Click on start attack.

![image](https://github.com/user-attachments/assets/1ec4ed92-46f9-4f04-81a3-db493c7954bc)

Now we have the admin's password - 

Login as admin to solve the lab.

![image](https://github.com/user-attachments/assets/8d23b1a2-d838-4b94-b045-ecc8ed79cee6)


## LAB 4 - Exploiting NoSQL operator injection to extract unknown fields

### Lab Description :

![image](https://github.com/user-attachments/assets/cb7be254-a159-411b-9396-39c8b67b349d)

### Solution :

The requirement of the lab is to exploit **NoSQL injection** vulnerabilities to extract **invisible fields** and log in to the account of the user **carlos**.

First, I logged in with an arbitrary account to capture the login request using **Burp Suite Proxy**.  
This allows us to analyze the structure of the request and begin crafting injection payloads for further exploitation.

![image](https://github.com/user-attachments/assets/db72dd5d-3ab1-4d5a-ac38-4e04c8492358)

In the http history we can see the login request

![image](https://github.com/user-attachments/assets/14b23121-8e7b-4019-b92e-5823887bd9d6)


We used the payload `"password":{"$ne":"invalid"}` to log in as the user **wiener**, and the login was successful.

This confirms that the application is vulnerable to **NoSQL operator injection**, allowing us to bypass authentication by injecting a condition that always evaluates to true.

![image](https://github.com/user-attachments/assets/9bdc1ed4-f69c-43ba-a178-52daa3a9786b)


However, when we used the same payload for the user **carlos**, the application responded with:

```

Account locked: please reset password

```

![image](https://github.com/user-attachments/assets/ff1975e6-2593-4cf6-8d2e-417a4806db69)


I used the following payload to test for NoSQL injection with a conditional time delay:

```json
{
  "username": "carlos",
  "password": { "$ne": "invalid" },
  "$where": "sleep(5000)"
}
````

This payload checks if we can bypass authentication for the user **carlos** and simultaneously confirms that the `$where` clause is being executed by the database.

As expected, the server **delayed its response by 5 seconds**, confirming successful evaluation of the `$where` clause and presence of a **NoSQL injection vulnerability**.

![image](https://github.com/user-attachments/assets/274349b5-d64b-4980-bf67-898d3d445ef4)


### Extracting available field names -

Send the above request to repeater.

- Replace the `$where` parameter with this `"$where":"Object.keys(this)[0].match('^.{}.*')"` .
- Add 2 payload positions to bruteforce - `"$where":"Object.keys(this)[0].match('^.{§§}§§.*')"`


> 1. `"$where"`: This is a key in a JSON object, and it seems to be used to define a condition or filter.
>
> 2. "`Object.keys(this)[0]"`: This part of the expression is JavaScript code, not a regular expression. It's using the **Object.keys(this)** function to get an array of keys of the current object (this), and then [0] is used to access the first key in that array. So, it's essentially accessing the first key in the current object.


![image](https://github.com/user-attachments/assets/250be184-9b41-4be0-b413-7cf1e1ec73f1)


Set Attack Type - Cluster Bomb
Payload 1 - Numbers from 0-20
Payload 2 - Simple list - `a-z`, `A-Z`, `0-9`

Once the attack is over, sort **Payload1** & **Length** to find the **1st key field which is `id`**.

![image](https://github.com/user-attachments/assets/4e276c18-fb6d-44a1-83ee-485e475ba6f8)


- Repeat the attack by changing hte position from 1 to 2 in the array - `"$where":"Object.keys(this)[1].match('^.{§§}§§.*')"`

This time we got the **value of 2nd key - `username`**

![image](https://github.com/user-attachments/assets/c83fbd27-39f9-47d4-83f6-804ba52c4445)



- Repeat the process for **3nd key field**, we got the value of 3rd field as - `password`
 
![image](https://github.com/user-attachments/assets/004299e8-2a6c-47e0-ae8b-02c91950e9ae)


- Repeat the process for 4th key field, we got the value of 4th field as - `newpwdTkn`

> **Before bruteforcing the 4th field (which most probably is the password reset field), make sure to send a password reset link for carlos before performing the bruteforce for 4th field.** Else you will get `500 Internal server error` when you bruteforce.

![image](https://github.com/user-attachments/assets/9d443e53-15aa-4257-8b68-0d1e2d60a509)

![image](https://github.com/user-attachments/assets/4fbd6bb2-b88b-4195-b5a4-334ce89d249d)

### Bruteforcing the password reset token in 4 field which we have identified above -

So where can we use the following fields which we identified? Possibly the **forgot-password** request.

Send the *GET /forgot-password* request to repeater. Add the parameter **?newpwdTkn=<invalid-token>**.In the response, we get **Invalid token** as expected.

![image](https://github.com/user-attachments/assets/b6feb330-c633-4488-a78f-1487687a55cc)

Now we need to extract the **`pwResetTkn`** (password reset token) field from the **carlos** account.

To do this, I used the following `$where` payload to brute-force the token character by character:

```json
"$where": "this.pwResetTkn.match('^.{$$}$$.*')"

```

* In the **first stage**, I used numeric values from `0` to `20` to determine the **length** of the token by observing when the response changes.
* In the **second stage**, I used a character set composed of **lowercase letters, uppercase letters, and numbers** to extract the token **one character at a time**, by matching each character position using a regular expression pattern.

This method allows us to exfiltrate the full token through **NoSQL injection with regex-based enumeration**.

![image](https://github.com/user-attachments/assets/22ca0cda-d9f8-4b2c-8bf7-e0003d01e738)


After the attack finish, we found a **16-character token**.


![image](https://github.com/user-attachments/assets/f0d9678c-ff84-44fc-be95-99c105cdfe23)



Replace the found token into the request:

```

GET /forgot-password?pwResetTkn=...

```

and send it. We received a response containing the **password change form**.

![image](https://github.com/user-attachments/assets/3e8062e6-d262-458b-b1ac-8702a9274541)



Change password and login to user carlos. Complete lab.

![image](https://github.com/user-attachments/assets/1691529b-995e-4691-8bde-5d507ebe3696)

