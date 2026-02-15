# Insecure Deserialization Overview

## Lab Levels

Jump directly to the lab writeups:

* [APPRENTICE](./APPRENTICE_Lab.md)
* [PRACTITIONER](./PRACTITIONER_Lab.md)
* [EXPERT](./EXPERT_Lab.md)

  
## Introduction

## 📦 What is Serialization?

Serialization (also known as marshaling, pickling, freezing, or flattening) is the process of converting complex data structures (like objects and their attributes) into a stream of bytes or string format that can be:

* Written to files or databases
* Transmitted over a network (APIs, messaging apps, etc.)
* Stored and later reconstructed (deserialization)

**Common formats include:**

### Binary Formats

* Java Serialization
* Ruby Marshal
* Protocol Buffers (Protobuf)
* Apache Thrift
* Apache Avro
* .NET Binary Format (MS-NRBF)
* Android Parcel
* IIOP

### Hybrid Formats

* PHP Serialization
* Python Pickle
* BSON (Binary JSON)

### Readable Formats

* JSON
* XML
* YAML

---

## ⚠️ What is Insecure Deserialization?

Insecure deserialization happens when user-controllable serialized data is deserialized by the application without proper validation or integrity checks.

This can allow an attacker to:

* Manipulate the data structure
* Inject malicious objects
* Trigger unintended method calls
* Achieve Remote Code Execution (RCE), privilege escalation, or data exfiltration

<img width="950" height="809" alt="image" src="https://github.com/user-attachments/assets/bee84850-dc1c-4548-91b6-2268e919ed06" />

---

##  Common Scenarios & Examples

### PHP Example:

**Serialized Object:**

```php
O:4:"User":2:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:0;}
```

**Payload after tampering:**

```php
O:4:"User":2:{s:8:"username";s:6:"carlos";s:7:"isAdmin";b:1;}
```

If the code does:

```php
$user = unserialize($_COOKIE['user']);
if ($user->isAdmin) {
  // Show admin panel
}
```

The attacker gains unauthorized admin access.

---

### Java Example:

Serialized Java objects use a binary format:

* Hex: `ac ed`
* Base64: `rO0...`

Payloads can be crafted using tools like:

* **ysoserial** ([https://github.com/frohoff/ysoserial](https://github.com/frohoff/ysoserial))
* **marshalsec**

Watch for:

* `readObject()` usage
* `java.io.Serializable` objects

---

##  How to Identify Serialized Data

* Look for strings in cookies, URL parameters, hidden fields that resemble serialized data formats.
* PHP serialized objects often start with `O:` and contain type/length indicators.
* Java objects encoded in base64 may start with `rO0...`.

---

##  Common Attacks

* Modifying serialized attributes (e.g., `isAdmin`)
* Using gadget chains for RCE (remote code execution)
* Triggering file reads or writes
* Denial-of-service via large object graphs
* PHP `phar://` deserialization

---

##  Lab-Based Exploit Examples

* Identifying and decoding serialized data in requests
* Modifying and re-encoding serialized PHP objects
* Triggering vulnerable deserialization logic in Java apps
* Exploiting PHP PHAR deserialization through file upload and file inclusion vectors



---

## 🔗 Tools

* [Burp Suite Pro](https://portswigger.net/burp) - automatically detects serialized objects
* [PHPGGC](https://github.com/ambionics/phpggc) - PHP gadget chains
* [ysoserial](https://github.com/frohoff/ysoserial) - Java gadget chains

---

## 🧠 Summary

Serialization is necessary for transmitting objects but introduces risk when mishandled. Insecure deserialization can lead to severe vulnerabilities such as RCE, privilege escalation, or complete application compromise. Use strict validation, limit deserialization from untrusted sources, and prefer secure serialization formats.

Stay alert. Always validate and verify before you deserialize.

---

