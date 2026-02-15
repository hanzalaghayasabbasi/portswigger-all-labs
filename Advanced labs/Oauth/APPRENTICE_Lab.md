## Labs Covered

This write-up focuses on the following **APPRENTICE-level lab** from the PortSwigger Web Security Academy related to **OAuth Authentication**:

**1 Authentication bypass via OAuth implicit flow**
<blockquote>
This lab demonstrates how attackers can exploit weaknesses in OAuth implicit flow to bypass authentication mechanisms.
</blockquote>

---

### LAB 1 - Authentication bypass via OAuth implicit flow

### Lab Description

<img width="880" height="352" alt="image" src="https://github.com/user-attachments/assets/b5f0b0e0-d072-4821-8aa3-87786f06c439" />

### Solution

Implicit Grant Type is used as OAuth Grant Type in Lab. The difference of the Implicit Grant Type is that the access token is sent immediately after the user approves. It is less reliable because all communication is routed through the browser.

First when I clicked on my account ,it Is telling me it is redirecting me to social media account.

<img width="1758" height="462" alt="image" src="https://github.com/user-attachments/assets/efee1e66-bdcf-4ab1-8c3f-d6f72c5679f9" />

The above interception request gives us  **GET /auth** request. This request defines the client application’s access permissions to the OAuth service. There are many parameters and they are all used in different definitions.

**Note**:We can read above  implict or Authorized code section to know what is happening in the request


<img width="1875" height="466" alt="image" src="https://github.com/user-attachments/assets/9d9c3130-36cc-422e-81b8-b142f52076ad" />



After Redirecting we can see Sign Up page which will come up on the screen


<img width="1434" height="563" alt="image" src="https://github.com/user-attachments/assets/eb0ac86c-6136-4308-8824-e1f9efcbd991" />


Now login as wiener and peter credential

<img width="713" height="531" alt="image" src="https://github.com/user-attachments/assets/73774f2d-18c0-4163-9ab4-ad72e10208a5" />


Afer clicking on above sign  we can see below what things website is taking we click on continue

<img width="712" height="501" alt="image" src="https://github.com/user-attachments/assets/e40bbca1-9649-4656-9616-675accee02e0" />


Now Above request Interception we can see below,Then sending it to repeater

<img width="1553" height="616" alt="image" src="https://github.com/user-attachments/assets/5801c666-e9fb-4ed9-888e-d7f3727e6f83" />


After Sending request  from above valid account of wiener it is giving us 302  redirection request

<img width="1722" height="527" alt="image" src="https://github.com/user-attachments/assets/d27050e9-5559-4830-9696-9e8f9d671214" />

 

change the email address to `carlos@carlos-montoya.net` and send the request. Observe that you do not encounter an error.


<img width="1717" height="517" alt="image" src="https://github.com/user-attachments/assets/175b5f63-ef3f-4341-8997-b4b630adf66f" />


Right-click on the **POST request and select "Request in browser" > "In original session"**. Copy this URL and visit it in the browser. 


<img width="1784" height="594" alt="image" src="https://github.com/user-attachments/assets/7ad8a67c-b7d8-4ba3-b5f0-0183f5727f70" />



 You are logged in as Carlos and the lab is solved.

<img width="1276" height="555" alt="image" src="https://github.com/user-attachments/assets/a12a7646-cf00-4b20-ac75-044d62fd606c" />


---

