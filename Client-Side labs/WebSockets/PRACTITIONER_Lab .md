## Labs Covered

This write-up focuses on the following **PRACTITIONER-level labs** from the PortSwigger Web Security Academy related to **WebSockets**:

**Cross-site WebSocket hijacking**  
This lab demonstrates how attackers can hijack WebSocket connections across origins, exploiting trust relationships and insecure implementations.

**Manipulating the WebSocket handshake to exploit vulnerabilities**  
This lab shows how attackers can manipulate WebSocket handshake headers to exploit vulnerabilities during connection establishment.

---

### LAB 2 - Cross-site WebSocket hijacking

### Lab Description

<img width="874" height="513" alt="image" src="https://github.com/user-attachments/assets/6ebcd791-d133-49f1-8bae-e2c6ea5ceb65" />

## What is Cross-Site WebSocket Hijacking?

**Cross-Site WebSocket Hijacking (CSWSH)**, also known as **Cross-Origin WebSocket Hijacking**, is a vulnerability that results from a **CSRF flaw in the WebSocket handshake process**.

### How It Works

* The vulnerable application uses **HTTP cookies** for authenticating WebSocket connections.
* It **does not implement CSRF protection** such as tokens or unpredictable headers.
* An attacker creates a **malicious web page** on a different origin.
* When a **victim user** (who is already authenticated) visits the attacker’s page:

  * A **WebSocket connection** is made from the attacker’s page to the vulnerable application.
  * The **server accepts the handshake** because it trusts the cookies automatically sent by the browser.
  * The attacker can now:

    * Send arbitrary WebSocket messages as the victim
    * Receive and read responses from the server

### Impact

* The attacker achieves **two-way interaction** with the server in the context of the victim’s authenticated session.
* This can lead to:

  * Unauthorized actions on behalf of the user
  * Sensitive data leakage
  * Full session compromise

---

### Solution

The lab application is a shop website offering chat support. After loading the page, I go straight to the chat feature and start chatting with the agent:

<img width="598" height="194" alt="image" src="https://github.com/user-attachments/assets/051b130c-2e22-44dd-ba08-cf930dae18b4" />

<img width="1147" height="465" alt="image" src="https://github.com/user-attachments/assets/bb1103b3-2d72-4187-b1da-1766af0816de" />


The next thing is to look at the handshake to see how the WebSocket is established:

<img width="1071" height="465" alt="image" src="https://github.com/user-attachments/assets/2a46e6ce-1ea9-4e51-97f4-d2462b3075b8" />

There is a single identifying feature in the request, the session cookie, without any protection against CSRF attacks.
The cookie is automatically sent by the browser. If I create my own web application that utilizes this WebSocket, I can therefore use this connection to perform any action and read any data the victim has access to.
What is also noteworthy is that once the WebSocket connection is established, the server sends the full history of the chat. This is noticeable on the chat page. No matter how often I reload the page, the full chat history is displayed.

If I can utilize this connection to retrieve the chat content of my victim, I may be able to find useful information.

## Craft malicious application

Let's start the malicious application. The WebSocket page on javascript.info provides a good example to follow. The chat always starts with a READY message, so I reproduce this.

<img width="882" height="247" alt="image" src="https://github.com/user-attachments/assets/895bcfe1-de4a-4f03-8399-3164223858cb" />

Once I open the page, I get my full chat history displayed:

### Option 1: Burp Collaborator

As a first option, I can exfiltrate using the Burp Collaborator. This requires a Burp Suite Professional license but is very convenient. See option 2 below for the non-Burp Pro solution.

<img width="1667" height="63" alt="image" src="https://github.com/user-attachments/assets/755088f2-1719-4580-a5b0-1ad60175b2e0" />

This does not prevent the exfiltration of the chat data as it refers to the connection to the collaborator URL, not the WebSocket. In my Burp Collaborator client, I get all my chat history.

If I want to get rid of these error messages, the documentation on mozilla.org leads to the RequestMode. Setting this to no-cors stops the errors.

After delivering the exploit to my victim, I check the Burp interactions and see some:


The messages are out of order, but going through the requests the following conversation is visible:

<img width="1112" height="298" alt="image" src="https://github.com/user-attachments/assets/c2757acb-86e8-4f6b-8143-d9961f85b0a7" />


### Option 2: Exploit Server Log

As an alternative to Burp Suite Professional, I can also use the Access Log feature of the exploit server. For this, I need to replace the fetch URL with my exploit server:


<img width="1029" height="260" alt="image" src="https://github.com/user-attachments/assets/3139280c-4cce-4d64-8bfb-1706cc9881f2" />

After delivering the exploit to the victim, the chat contents are visible in the Access log of the exploit server:

<img width="1159" height="143" alt="image" src="https://github.com/user-attachments/assets/a172271b-d2ad-483f-8b1c-128172fc61a4" />

whichever way was used to obtain username and password, using them allows me to log in to the application and the lab updates to solved


---

### LAB 3 - Manipulating the WebSocket handshake to exploit vulnerabilities

### Lab Description

<img width="890" height="503" alt="image" src="https://github.com/user-attachments/assets/1e3aa81a-75b7-4d88-a2a1-b7e3cdc37cf3" />


## Overview: What is Cross-Site WebSocket Hijacking? 

**Cross-Site WebSocket Hijacking (CSWSH)** is a vulnerability that allows an attacker to hijack a user's authenticated WebSocket session.

### Key Concept: 

It exploits a **lack of CSRF protection** during the **WebSocket handshake**—when authentication is based only on **cookies**, without verifying any **unpredictable tokens**.

### How it works: 

1. The victim is authenticated on a vulnerable website using cookies.
2. The attacker lures the victim into visiting a malicious site.
3. The malicious site uses JavaScript to initiate a **WebSocket connection** to the target application.
4. Because cookies are automatically sent, the server treats the connection as authenticated.
5. The attacker now gains **two-way communication** with the server in the victim’s session context.

### Impact: 

* Full control over WebSocket-based features
* Read and send messages as the victim
* Potential data leakage or account compromise

---



### Solution



First I intercept the WebSocket request on client side.

<img width="1897" height="623" alt="image" src="https://github.com/user-attachments/assets/69d9c269-f373-4e1b-b2e3-9384b9cae010" />

 I think these type of payload is block and that have blocked our ip.

 <img width="1914" height="840" alt="image" src="https://github.com/user-attachments/assets/80115263-f791-48fb-9d35-63e6b5dab938" />


 So add `x` forwarded header so it will change our ip.

<img width="1896" height="588" alt="image" src="https://github.com/user-attachments/assets/dde3edf0-8431-4018-a147-bdc950366ef0" />



 Now if we give same payload above it will block our ip ,So we have change our paylaod Now it will trigger alert and lab will be solved.

 <img width="1870" height="715" alt="image" src="https://github.com/user-attachments/assets/09ecbcea-fe03-4a79-a575-56171fd4c62b" />
