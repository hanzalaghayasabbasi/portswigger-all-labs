## Labs Covered

This write-up focuses on the following **APPRENTICE-level labs** from the PortSwigger Web Security Academy related to **Cross-site scripting (XSS)**:

**Reflected XSS into HTML context with nothing encoded**  
This lab demonstrates a reflected XSS vulnerability where no output encoding is performed in the HTML context.

**Stored XSS into HTML context with nothing encoded**  
This lab shows how stored XSS can occur when user input is stored and later rendered without encoding.

**DOM XSS in document.write sink using source location.search**  
This lab explores DOM-based XSS vulnerabilities via `document.write()` using URL query parameters as a source.

**DOM XSS in innerHTML sink using source location.search**  
This lab shows DOM XSS occurring when `innerHTML` is assigned unsanitized URL parameter values.

**DOM XSS in jQuery anchor href attribute sink using location.search source**  
This lab demonstrates DOM XSS by manipulating jQuery selectors that use anchor `href` attributes sourced from URL parameters.

**DOM XSS in jQuery selector sink using a hashchange event**  
This lab shows how DOM XSS can be triggered through jQuery selectors reacting to the `hashchange` event.

**Reflected XSS into attribute with angle brackets HTML-encoded**  
This lab explores reflected XSS where angle brackets are encoded but the payload still executes.

**Stored XSS into anchor href attribute with double quotes HTML-encoded**  
This lab demonstrates stored XSS in anchor href attributes even when double quotes are encoded.

**Reflected XSS into a JavaScript string with angle brackets HTML encoded**  
This lab shows how reflected XSS can occur inside JavaScript strings despite angle bracket encoding.

---

### LAB 1 - Reflected XSS into HTML context with nothing encoded

### Lab Description

![image](https://github.com/user-attachments/assets/946062f7-4238-4663-9561-352e5200e0c9)

### Solution


There is a search functionality that takes the user input and uses it to generate the next HTML code.

![image](https://github.com/user-attachments/assets/a3aeb0c8-19bc-4967-a94e-b1e98a5ef178)

![image](https://github.com/user-attachments/assets/7c4aaeb3-2fbc-4401-8952-d1835aff2681)


Searching `“<script>alert(1)</script>”` you see the alert popping:

![image](https://github.com/user-attachments/assets/10a1a66a-d711-4921-8295-96d1714e47ce)

After alert pop lab will be solved

![image](https://github.com/user-attachments/assets/6b935a66-5189-40eb-80b8-99258daa730c)


---

### LAB 2 - Stored XSS into HTML context with nothing encoded

### Lab Description


![image](https://github.com/user-attachments/assets/67d442be-10fa-4961-a934-31c27c1f76f4)


### Solution

There is a functionality to post comments in each blog post:

![image](https://github.com/user-attachments/assets/dbe9ac9c-84a8-45d0-aae5-d61d5df8b9c8)


If you check the blog post again you see the alert popping:

![image](https://github.com/user-attachments/assets/ae9b061e-ec4b-429c-a917-d6bb4b6ea658)


After alert pop lab will be solved

![image](https://github.com/user-attachments/assets/40fa62fe-fda0-4b2b-93d2-f50e5d966682)

---

### LAB 3 - DOM XSS in document.write sink using source location.search

### Lab Description

![image](https://github.com/user-attachments/assets/92a92b62-19da-411f-94bb-03a506523d50)


### Solution

There is a search function in "/?search=":

![image](https://github.com/user-attachments/assets/e222c3dd-bcd8-48db-8033-ecae3fba8d8f)

In the source code we see the sink:

![image](https://github.com/user-attachments/assets/bd3de0f2-d723-4e14-a51c-f6f80b79075e)


We can pop an alert with the payload:

``` "><script>alert(1)</script> ```

![image](https://github.com/user-attachments/assets/19aac27b-cdad-4bb9-8947-471490f7fb57)


After alert pop lab will be solved

---

### LAB 4 - DOM XSS in innerHTML sink using source location.search

### Lab Description

![image](https://github.com/user-attachments/assets/3d665930-559c-4455-84e2-298d022e5aed)


### Solution


There is a search function in "/?search=":

![image](https://github.com/user-attachments/assets/5bc336d6-b9c9-4abe-8e14-b68f57ecf069)

In the source code we see the sink:

![image](https://github.com/user-attachments/assets/a9c0a884-858d-451c-bc4c-8432cce6e2a7)


The HTML content of the searchMessage, a span HTML element, is generated from the content of the “search" GET parameter of the request. We can pop an alert with the payload:

```
<img src=x onerror=alert(1) />

```

![image](https://github.com/user-attachments/assets/b9e83bad-41a3-4e94-9df3-2c08905b83dd)


After alert pop lab will be solved

---

### LAB 5 - DOM XSS in jQuery anchor href attribute sink using location.search source

### Lab Description


![image](https://github.com/user-attachments/assets/4d7f7c9b-fe1c-4f3a-8780-d94e868977c7)



### Solution

This is the sink in the "Submit Feedback" page:

![image](https://github.com/user-attachments/assets/e7bb9544-65ab-455b-ab84-fe17c782e8f5)


And the url of the "Submit Feedback" page is  `https://0af5007903b0426b803b4e9100cb0023.web-security-academy.net/feedback?returnPath=/:`

![image](https://github.com/user-attachments/assets/9898e542-9c0b-468f-87af-c0a1e97383c7)

It is possible to use a Javascript url link

```

/feedback?returnPath=javascript:alert(document.cookie) 

```

![image](https://github.com/user-attachments/assets/ed266f20-0e11-44a5-8344-411f8835a355)


After alert pop lab will be solved

---

### LAB 6 - DOM XSS in jQuery selector sink using a hashchange event

### Lab Description

![image](https://github.com/user-attachments/assets/41da8481-d299-4168-9f74-15f70f0f5467)

### Solution

This is the problematic code in the Home page:
```
$(window).on('hashchange', function(){
    var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
    if (post) post.get(0).scrollIntoView();
});

```


![image](https://github.com/user-attachments/assets/d8c793fe-ebe4-457f-b82e-9195d6771dd6)

To exploit it, it is possible to use the same payload as in  `https://portswigger.net/web-security/cross-site-scripting/dom-based `:

Payload we used = <iframe src="https://YOUR-LAB-ID.web-security-academy.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>

Deliver exploit to victum and lab will be solved

![image](https://github.com/user-attachments/assets/46c05e1f-df41-4894-b762-361c33934ed5)


---

### LAB 7 - Reflected XSS into attribute with angle brackets HTML-encoded

### Lab Description

![image](https://github.com/user-attachments/assets/19ea5936-1e8c-45c8-8d2d-139d0227a073)

### Solution

![image](https://github.com/user-attachments/assets/282a3b61-12c7-4267-80aa-5bbf48709144)

When we search “aaaa” it becomes the “value” of this HTML element:

![image](https://github.com/user-attachments/assets/40431463-9ce1-437b-90dc-a5efbefbd9a7)

With this payload the alert pops:

```
" autofocus onfocus=alert(1) x="

```

![image](https://github.com/user-attachments/assets/991a1db6-a38a-4bae-9615-d24c6b84b907)


---

### LAB 8 - Stored XSS into anchor href attribute with double quotes HTML-encoded

### Lab Description

![image](https://github.com/user-attachments/assets/ee56b892-e658-465b-bcec-7544efd67450)

### Solution

It is possible to post comments:

![image](https://github.com/user-attachments/assets/750ecc35-7274-4ee7-a985-be43d80abbf0)

This is the HTML element generated:

![image](https://github.com/user-attachments/assets/f4f5d71d-aa69-4d0e-a1d9-93393bcd28cc)

When the user name is clicked, it redirects to the website set in the comment:

![image](https://github.com/user-attachments/assets/748e8be6-8bdf-4203-a018-164d3dde882f)

We will set the website to a javascript url:

```
javascript:alert(1)
```

![image](https://github.com/user-attachments/assets/6231b38f-8185-4a91-bed4-40a5977a286c)


When clicked, the alert pops:

![image](https://github.com/user-attachments/assets/c135911a-9103-4f3b-aefc-1234131d626c)

After alert pop lab will be solved

---

### LAB 9 - Reflected XSS into a JavaScript string with angle brackets HTML encoded

### Lab Description

![image](https://github.com/user-attachments/assets/03e22515-3119-47ef-b091-d0a38d05c73d)

### Solution

![image](https://github.com/user-attachments/assets/acb7ed91-3e31-4888-a958-1f6f681fa0b0)

When we search **“aaaa”**, it generates a page with the following code:

![image](https://github.com/user-attachments/assets/5d7801fa-1674-4576-bad1-6ca3bfc3ee82)

With a payload like:

![image](https://github.com/user-attachments/assets/fd403cf4-3b70-4edd-bebe-51a4aefcf21f)

We see the code is now:

![image](https://github.com/user-attachments/assets/5a52dd6b-b1c9-40a9-a31e-a6b0953b0e79)

With this payload the alert pops:

![image](https://github.com/user-attachments/assets/71025f7a-9a8b-46be-b81b-51080a2ce16b)

![image](https://github.com/user-attachments/assets/7f67932d-220b-4685-b805-9d071e03b8a8)


After alert pop lab will be solved

---
