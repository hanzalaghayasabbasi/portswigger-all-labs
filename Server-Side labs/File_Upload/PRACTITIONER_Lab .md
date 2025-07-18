## Labs Covered

This write-up focuses on the following **PRACTITIONER-level labs** from the PortSwigger Web Security Academy:

- **Web shell upload via path traversal**  
  This lab demonstrates how attackers can abuse directory traversal vulnerabilities during file upload to place web shells into executable directories, resulting in remote code execution.

- **Web shell upload via extension blacklist bypass**  
  This lab shows how attackers can bypass file extension blacklists by manipulating filenames to evade validation checks, enabling successful web shell uploads.

- **Web shell upload via obfuscated file extension**  
  This lab demonstrates how attackers can craft filenames with obfuscated extensions (using techniques such as Unicode characters, null bytes, or multiple extensions) to bypass file validation mechanisms.

- **Remote code execution via polyglot web shell upload**  
  This lab shows how attackers can craft polyglot files that satisfy multiple file type checks simultaneously, allowing them to upload executable files disguised as safe file types and achieve remote code execution.

---

## LAB 3 - Web shell upload via path traversal

### Lab Description :
![image](https://github.com/user-attachments/assets/39a7b69d-d6ac-4396-9580-647a0290ae93)


### Solution :

The default credentials that we have are wiener:peter.We login with that credential

Next, I will upload a malicious file with a `.php` extension. I have named the malicious file `myexploit.php`.

In the screenshot below, you can see that I have highlighted two important requests captured in Burp Suite:

1. The **GET** request — this reveals the location of the uploaded image on the server.
2. The **POST** request — this is responsible for uploading the `myexploit.php` file to the server.

To proceed with testing and analysis, I will forward both of these requests to the **Repeater** tab in Burp Suite. This allows me to modify and resend the requests manually to observe the server’s behavior and confirm if the malicious file upload was successful.


![image](https://github.com/user-attachments/assets/5a9d097e-1263-4642-9b99-fe5eedd300e2)

After sending both requests to the Repeater tab in Burp Suite, I renamed them for better clarity and organization.

The **POST** request, which is responsible for uploading the malicious file (`myexploit.php`), was renamed to **UploadImage**. This request is used to interact with the file upload functionality.

The **GET** request, which is used to view the location of the uploaded file on the server, was renamed to **ShowImage**. This helps in easily identifying and man

![image](https://github.com/user-attachments/assets/015ea60e-6462-49c8-8ca5-ba9581899a6d)

As you can see in the screenshot below, I initially changed the filename to `../exploit.php` in an attempt to perform a directory traversal and place the file into the parent directory.

However, simply using `../` may not work, as many web applications sanitize or block forward slashes (`/`). To bypass this restriction, we need to **obfuscate the forward slash** by URL encoding it. The encoded value of `/` is `%2f`.

Therefore, I modified the filename to `..%2fmyexploit.php`. This encoding helps bypass basic filtering and allows us to attempt writing the file in the **parent directory**, which, in this lab scenario, has **executable permissions**.

The file I uploaded is named `myexploit.php`, and it contains the following PHP payload:

```php
<?php echo system($_GET['command']); ?>
```

![image](https://github.com/user-attachments/assets/99fbf915-894b-43d8-9080-74dbb0fdb683)

Now that our file has been successfully uploaded to the **previous directory**, we can access it by modifying the URL. Originally, uploaded files are served from the `/avatar/` directory. However, since we used a path traversal technique (`..%2f`) during the upload, our file (`myexploit.php`) was placed in the **parent directory** of `/avatar/`.

![image](https://github.com/user-attachments/assets/c679552f-803b-4bc8-a2e2-4dbaefe5421f)

Submit the secret to solve the lab.

![image](https://github.com/user-attachments/assets/1798cfe6-c365-45cb-a231-1c8695168262)

---

## LAB 4 - Web shell upload via extension blacklist bypass

### Lab Description :

![image](https://github.com/user-attachments/assets/26e86041-d17f-4c13-90ac-7df894f4f3a2)



### Solution :

(Solution content would go here)

---

## LAB 5 - Web shell upload via obfuscated file extension

### Lab Description :

![image](https://github.com/user-attachments/assets/37ecae73-08d3-4631-93d0-75a036bed721)

## Overview:

One of the more obvious ways of preventing users from uploading malicious scripts is to blacklist potentially dangerous file extensions like `.php`. However, the practice of blacklisting is inherently flawed, as it's difficult to account for every possible variation that could be used to execute code.

Attackers can often bypass these blacklists by using **lesser-known or alternative extensions** that are still interpreted by the server as executable. Examples of such extensions include:

- `.php5`
- `.php7`
- `.phtml`
- `.shtml`
- `.phar`
- `.php4`
- `.pht`

Because web servers like Apache and Nginx may be configured to treat these extensions the same as `.php`, relying solely on extension blacklisting is an insecure approach to file upload validation.

### Solution :

Login as wiener to access the upload functionality.

Upload a **.php** file with the following payload `<?php phpinfo() ?>`.`

![image](https://github.com/user-attachments/assets/1eab82ac-e03a-4a0e-853c-d60da4c0a892)

I have also attempted to bypass the extension blacklist by using a **double extension** technique, naming the file as `phpinfo.jpg.php`. This method is commonly used to trick file upload filters that only check the last extension or expect image formats like `.jpg` or `.png`.

However, in this case, the **server is still blocking the upload**, indicating that it is performing more strict validation. It likely checks the **entire filename**, not just the final extension, and explicitly denies files with any suspicious patterns involving `.php`.

![image](https://github.com/user-attachments/assets/d6aef37f-9042-42f4-91c0-a70800c7f5b0)

Now, I have successfully uploaded a file with a `.phtml` extension by exploiting the file upload vulnerability. The server did not block this extension, which is still treated as executable by many PHP interpreters.

![image](https://github.com/user-attachments/assets/73610f40-d17d-4564-aa90-79b6cfdaa06a)


After uploading the malicious `.phtml` file, I accessed it through the browser. The PHP payload executed successfully, confirming that code execution was achieved.


Then, I changed the payload to the following:

```php
<?php echo file_get_contents('/home/carlos/secret'); ?>

```

![image](https://github.com/user-attachments/assets/65fcf703-6fd6-457c-b6d4-ff14edf9cdce)

Result

![image](https://github.com/user-attachments/assets/41d2ab4c-993c-4866-864b-8817cce2a3ee)


I then copied the key and sumbit it, **the lab is successfully solved**.

![image](https://github.com/user-attachments/assets/0af85376-2707-42c1-94fe-9b216d03f9a5)

---

## LAB 6 - Remote code execution via polyglot web shell upload

### Lab Description :

![image](https://github.com/user-attachments/assets/de77f43b-2308-4fe0-9c9f-d3ee6a3f9e54)


### Solution :

In this lab, we are exploiting a **Remote Code Execution (RCE)** vulnerability through an insecure file upload function. Despite any basic protections in place, we are still able to upload files and execute our code on the server-side. The main objective is to upload a PHP web shell and access the `/home/carlos/secret` file in order to obtain the key and solve the lab.

---

### Step 1: Upload a Basic PHP File

To begin testing the server's behavior, we first upload a simple PHP file named `phpinfo.php` with the following content:

```php
<?
php phpinfo();
?>
```

To bypass this, I changed the filename from `phpinfo.php` to `phpinfo.jpg` in an attempt to **trick the file extension filter**. However, this approach also failed, indicating that the server is performing **additional validation checks** — possibly analyzing the **file content** (MIME type) or blocking known file signature patterns associated with PHP.

This confirms that basic extension spoofing alone is **not sufficient** to bypass the upload restrictions in this scenario.

![image](https://github.com/user-attachments/assets/3f29455b-3e3d-4193-a40f-3139b9d1b210)

Now, go to Google and search for “magic number image search.” copy jpeg but failed to upload jpeg

![image](https://github.com/user-attachments/assets/eefeaad9-7e55-4696-af1e-7e7495890047)

Next, search for GIF on the wiki website and copy its magic characters.

![image](https://github.com/user-attachments/assets/47781e55-0786-428c-b26c-3bd462a47be3)

As you can see, the server accepted the **GIF magic bytes**, allowing us to bypass its file upload security mechanisms. By placing the correct **magic number** at the beginning of the file (i.e., `GIF89a`), we made the server believe that the uploaded file was a legitimate image, even though it contained embedded PHP code.

![image](https://github.com/user-attachments/assets/08b417e6-ca26-4892-b45c-5697e38f7a93)


To exploit this, I crafted a file starting with the GIF header, followed by the PHP payload:

```php
GIF89a
<?php echo file_get_contents('/home/carlos/secret'); ?>
```
![image](https://github.com/user-attachments/assets/d9c8a815-3b07-4281-bd1c-71e5fd4ec5ba)

Result:

![image](https://github.com/user-attachments/assets/1a7ad7ba-b43a-402e-83df-f48f76950562)

> 💡 **Note:** We can also use `exiftool` to embed our PHP payload into an image file as a comment, creating a **polyglot file** — one that appears to be a valid image but is also executable PHP code.

To do this, we use the following command:

```bash
exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" <YOUR-INPUT-IMAGE>.png -o polyglot.php
```

Submit the key to solve the lab.

![image](https://github.com/user-attachments/assets/fac1e00d-d4b9-4318-904a-b253b892b16e)

