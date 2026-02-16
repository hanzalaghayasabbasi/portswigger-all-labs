## Labs Covered

This write-up focuses on the following **PRACTITIONER-level labs** from the PortSwigger Web Security Academy related to **DOM-based vulnerabilities**:

**1 DOM XSS using web messages**  
<blockquote>
This lab demonstrates how attackers can exploit insecure handling of `postMessage` web messages to achieve DOM-based XSS.
</blockquote>


**2 DOM XSS using web messages and a JavaScript URL**  
<blockquote>
This lab extends the previous concept by leveraging JavaScript URLs to achieve DOM-based XSS through web messages.
</blockquote>


**3 DOM XSS using web messages and JSON.parse**  
<blockquote>
This lab explores how insecure parsing of untrusted messages using `JSON.parse` can lead to DOM XSS.
</blockquote>


**4 DOM-based open redirection**  
<blockquote>
This lab demonstrates how insecure handling of user input in redirects can allow DOM-based open redirection attacks.
</blockquote>

**5 DOM-based cookie manipulation**  
<blockquote>
This lab shows how attackers can exploit DOM vulnerabilities to manipulate cookies directly within the browser.
</blockquote>

---

### LAB 1 - DOM XSS using web messages

### Lab Description

<img width="853" height="257" alt="image" src="https://github.com/user-attachments/assets/cefa55b6-8683-4c36-b922-8eaca2466933" />


### Solution

As usual, the first step is to analyze the functionality of the lab application, in this case, a shop website.
What immediately jumps at me is a weird [object Object] string above the product listing:

<img width="850" height="483" alt="image" src="https://github.com/user-attachments/assets/1a937555-afd0-47e3-8d98-dda92941370a" />

With the help of the browser inspector, I review the corresponding part of the HTML:

<img width="557" height="122" alt="image" src="https://github.com/user-attachments/assets/bd7acf93-04fc-45d7-8fcd-082c3961d7a7" />

Whenever a message is sent to the window, an element of the DOM is changed. What is good news is that there are no forms of sanitization going on here, the raw message data is taken and put straight into the DOM.

## The theory;

If I can load the page in an **iframe** within a page I control, I can send arbitrary data to the application. A quick google search brought me to the [mozilla documentation for iframe](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe#scripting) . Interesting for the lab is the scripting information:

<img width="1061" height="287" alt="image" src="https://github.com/user-attachments/assets/6d3fc1b6-b275-4922-9e1f-d45e5d03e2dd" />

So I can access the window object of the lab application to send the message. I cannot inject a <script> tag straight away as the script parsing for the victim page is already finished.

To have the browser run my script I need to include it in a way that it runs while it tries to render the page, for example, in the onerror property of an <img> tag.

The Mozilla documentation also shows the correct syntax for sending a message to the window object of the iframe:

```

postMessage(message, targetOrigin)
postMessage(message, targetOrigin, transfer)

```

My payload will be transported in the **message**, while the targetOrigin is the target domain or a * as a synonym for the full world.

## The malicious page

Now I have all the information I require to craft a malicious page on the exploit server. As I care about the security of my exploit page, I use the full URL of my victim as targetOrigin:

<img width="843" height="301" alt="image" src="https://github.com/user-attachments/assets/d88d6fe3-54e0-4c70-961f-ed5ed736c7b8" />


Storing the exploit and viewing it opens the print dialog as expected. Directly after sending the exploit to the victim, the lab updates to solve

<img width="1341" height="241" alt="image" src="https://github.com/user-attachments/assets/2b76d260-342c-4210-8d22-69a8b4abe56d" />

---

### LAB 2 - DOM XSS using web messages and a JavaScript URL

### Lab Description

<img width="845" height="315" alt="image" src="https://github.com/user-attachments/assets/7a8242aa-7d37-4fc2-87a6-34ab825f36c1" />

### Solution

As usual, the first step is to analyze the functionality of the lab application, in this case, a blog website.
From plain browsing of the site, nothing is immediately obvious. So I turn to the source of the page and find an interesting script:

<img width="796" height="178" alt="image" src="https://github.com/user-attachments/assets/d2c35a99-9e00-4958-9e04-c5b1683f5557" />


When a message is received by the window, a check is performed whether it contains an http: or https:. If found to be so, the current location will redirect to the data value of the message.

## The theory

If I can load the page in an iframe within a page I control, I can send arbitrary data to the application. A google search brings me to the [mozilla documentation for iframe](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe#scripting). Interesting for the lab is the scripting information:

<img width="913" height="253" alt="image" src="https://github.com/user-attachments/assets/7401daa3-12f0-47e1-b2b8-0a36482301d6" />

So I can access the window object of the lab application to send the message. The Mozilla documentation also shows the correct syntax for sending a message to the window object of the iframe:

```

postMessage(message, targetOrigin)
postMessage(message, targetOrigin, transfer)

```
My payload will be transported in the message, while the targetOrigin is the target domain or a `*` as a synonym for the full world.

I need a payload that contains an http: or https:, it does not require it at the beginning of the string. No other validation is done on the content. As long as I ensure one of these strings is anywhere in my code, for example in a JavaScript comment, it will pass the validation.

In most browsers, using `javascript:alert("Hello World");` as URL will execute the code. As the code in the lab application puts whatever string I send straight into the URL.

## The malicious page:

If the payload contains “http:” or “https:”, it will redirect to that page.
Our payload in the exploit server:

```
<iframe src="https://0a0300fb03ec541d83b0e1af005a0096.web-security-academy.net/" onload="this.contentWindow.postMessage('https://as.com','*')" style="width:100%;height:100%">
```

When we click “View”, it redirects to **as.com**:


<img width="545" height="216" alt="image" src="https://github.com/user-attachments/assets/edca63b8-97b3-4097-9af8-c59038862fe6" />

We can execute Javascript code with javascript:alert(1). As there are already nested quotes and double quotes we can use the character “`” to create an alert message with the previous url, so the payload wil still have **“https:”**:

```
<iframe src="https://0a0300fb03ec541d83b0e1af005a0096.web-security-academy.net/" onload="this.contentWindow.postMessage('javascript:alert`https://as.com`','*')" style="width:100%;height:100%">


```


<img width="699" height="99" alt="image" src="https://github.com/user-attachments/assets/799b0741-9fae-4986-a593-5921008f2c74" />


If we change the payload to print the page:

```

<iframe src="https://0a0300fb03ec541d83b0e1af005a0096.web-security-academy.net/" onload="this.contentWindow.postMessage('javascript:print`https://as.com`','*')" style="width:100%;height:100%">

```

<img width="1385" height="324" alt="image" src="https://github.com/user-attachments/assets/eec4175b-cf41-4ed6-a0ba-b6d6541d9737" />


---

### LAB 3 - DOM XSS using web messages and JSON.parse

### Lab Description

<img width="864" height="267" alt="image" src="https://github.com/user-attachments/assets/258fbf2c-f882-4416-bfb3-f5f68d8bcf39" />


### Solution

As usual, the first step is to analyze the functionality of the lab application, in this case, a shop website.
After browsing the public pages I move on to the HTML source of the page. On the main page an interesting script can be found:


<img width="653" height="475" alt="image" src="https://github.com/user-attachments/assets/a4b83dca-05f4-40f3-a73f-ec59701b3b90" />


Whenever a message is received, the script creates an iframe and appends it to the current page. The message is then parsed as JSON and, depending on the message content, an action may be performed.
One of the possible actions is loading an URL contained in the message within the iframe.

## The theory

If I can load the page in an iframe within a page I control, I can send arbitrary data to the application. A google search brings me to the  [mozilla documentation for iframe](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe#scripting). Interesting for the lab is the scripting information:


<img width="919" height="250" alt="image" src="https://github.com/user-attachments/assets/2e6d545b-dead-44e0-8347-13c7132cf435" />

So I can access the window object of the lab application to send the message. The Mozilla documentation also shows the correct syntax for sending a message to the window object of the iframe:

```
postMessage(message, targetOrigin)
postMessage(message, targetOrigin, transfer)

```
My payload will be transported in the message, while the targetOrigin is the target domain or a * as a synonym for the full world.
The vulnerable script requires a valid JSON string in the message. It always contains a key type which can be one of page-load, load-channel or player-height-changed.
In case the type is load-channel, an additional key url is assumed to be present in the message which is then loaded into the iframe.
No further checks are done on the content of the message, so I can inject a JavaScript URL in there:

```

{
    "type": "load-channel", 
    "url": "javascript:print()"}

```

The malicious page

One question that always comes to mind when using strings is:
Which types of quotes to use, single or double?

For this lab, I need three nested layers of quotations
	• the content of onload
	• the argument for postMessage
	• the strings within the JSON
	
The JSON RFC 7159 requires strings within JSON to use double quotes, so I need to use them there. I already need both types of quotes for the iframe onload content and its argument, so I need to escape the double quotes within the JSON string:

```

<iframesrc="https://0a21004a048f2b53c0c70b7c004c0002.web-security-academy.net/" 
    onload='contentWindow.postMessage("{\"type\": \"load-channel\", \"url\": \"javascript:print()\"}","*");'
></iframe>

```

This results in my malicious HTML page:

<img width="943" height="591" alt="image" src="https://github.com/user-attachments/assets/5599e7fb-88a7-4d48-bbd4-f0a64c9d9b3e" />

After storing I test the exploit by viewing it. As expected, the print window opens. All that is left now is to deliver the exploit to the victim and the lab updates to solved

<img width="1189" height="185" alt="image" src="https://github.com/user-attachments/assets/67253486-d986-4aae-8c7a-6434e689d9e0" />

---

### LAB 4 - DOM-based open redirection

### Lab Description

<img width="897" height="284" alt="image" src="https://github.com/user-attachments/assets/49ce32f5-e682-4439-872f-89797e9ddd84" />

### Solution

As usual, the first step is to analyze the functionality of the lab application, in this case, a blog website. After I browse through the page, I go check the HTML sources. One interesting piece of HTML can be found:

<img width="674" height="104" alt="image" src="https://github.com/user-attachments/assets/b87f6138-c451-4a35-9433-6b56783f9048" />

This link is found under every blog article and is used to determine the target of the link dynamically. If there is no parameter url in the URL of the page, then it redirects to the local base /.
However, if the url parameter exists and starts with either `http://` or `https://`, it will be used as the destination of the link.
No further validation is performed on the destination target.

## The malicious link

Now I know how to craft a URL that redirects to any target of my choice.

https://0aa4001903e8eff4c0973a9a00d3008e.web-security-academy.net/post?postId=5&url=https://exploit-0a610014032cefa6c0983abd01bd00c8.web-security-academy.net/exploit

As soon as I load that URL, the lab updates to solved


<img width="667" height="114" alt="image" src="https://github.com/user-attachments/assets/08603e64-e95c-4ce4-938b-62bd822af754" />

---

### LAB 5 - DOM-based cookie manipulation

### Lab Description

<img width="846" height="296" alt="image" src="https://github.com/user-attachments/assets/272519ee-b9bd-4765-bf12-f0543cd672b1" />

### Solution


As usual, the first step is to analyze the functionality of the lab application, in this case, a shop website. After I browse through the page, I go check the HTML sources. One interesting piece of HTML can be found on the product pages:

<img width="657" height="99" alt="image" src="https://github.com/user-attachments/assets/72c7d7b4-0b62-4872-af62-786c008651a5" />


This script stores the current page by URL in the cookie.

<img width="665" height="336" alt="image" src="https://github.com/user-attachments/assets/cd59364f-95e2-4ac2-bc64-dfbc113cd556" />

From this moment onwards, the requests are sent with that cookie and the page contains a **Last viewed product link** at the top:

<img width="1095" height="317" alt="image" src="https://github.com/user-attachments/assets/09aa113c-de57-4b45-ae3b-05c2c2574527" />

<img width="669" height="247" alt="image" src="https://github.com/user-attachments/assets/37e8985a-c123-4ce7-a66d-bd10c76d16e9" />

First I test whether the application verifies that the target is within its own domain:


<img width="1240" height="211" alt="image" src="https://github.com/user-attachments/assets/dc894f7c-9add-412e-82e1-2a74cdff2f67" />

Next, I check if I can break out of the link and inject arbitrary HTML and JavaScript:

<img width="913" height="156" alt="image" src="https://github.com/user-attachments/assets/2ca4db16-2389-43b4-b988-e228eeb84906" />


Sure enough, the cookie value can be used to execute arbitrary JavaScript in the scope of the page.
The theory

The vulnerable script takes the raw input from window.location without any validation. Above, I verified that I can break out of the link context.
So I need to take a valid product URL and attach my payload in a way that the URL stays valid and produces a product page. For example, with an additional and completely fictional parameter:

```
https://0ae5007c0406e52ec028374700af0043.web-security-academy.net/product?productId=1&evil='><script>alert(document.domain)</script>

```

I test this URL in the browser and, sure enough, the alert() box shows up.

If I load that crafted URL in an iframe within a page I control, I can inject arbitrary JavaScript into the cookie. However, the initial display of the page just writes the cookie. It requires a reload to send the cookie to the server and include the JavaScript into the page.

It is unlikely that my victim is inclined to help me with this, therefore I need a way to automate this.

My initial thought was to use a script within my malicious page that sleeps for some milliseconds and then reloads the iframe. However, after searching a bit I found that sleep is not as trivial in JavaScript as it is in other languages I know.

But I found the documentation of [setTimeout](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/iframe#scripting](https://developer.mozilla.org/en-US/docs/Web/API/setTimeout)) which does what I want, albeit in an asynchronous way:

<img width="629" height="110" alt="image" src="https://github.com/user-attachments/assets/8695253a-3c56-4935-8891-b0290ccc29cd" />

### The malicious page

My malicious page loads the vulnerable product details page within an iframe, with my payload added as a URL parameter.
After a few milliseconds, the frame content gets redirected to the base URL of the shop, thus triggering the script.

```

<iframename="victim" id="victim"
    src="https://0ae5007c0406e52ec028374700af0043.web-security-academy.net/product?productId=1&'><script>print()</script>" 
></iframe><script>setTimeout(()=>{document.getElementsByName('victim')[0].src="https://0ae5007c0406e52ec028374700af0043.web-security-academy.net"},500);</script>

```
<img width="740" height="422" alt="image" src="https://github.com/user-attachments/assets/30552ddd-4c7d-4402-82c5-54ffc58dcdba" />

After delivering the exploit to the victim, the lab updates to solved

<img width="874" height="173" alt="image" src="https://github.com/user-attachments/assets/3a02055d-ad37-483f-ae62-df6acbf161f2" />

---






