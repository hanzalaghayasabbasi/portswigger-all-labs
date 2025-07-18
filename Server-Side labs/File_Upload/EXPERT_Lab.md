## Labs Covered

This write-up focuses on the following **EXPERT-level lab** from the PortSwigger Web Security Academy:

- **Web shell upload via race condition**  
  This lab demonstrates how attackers can exploit race conditions during file upload processing to bypass security controls and successfully upload malicious web shells, leading to remote code execution.

---

## LAB 7 - Web shell upload via race condition

### Lab Description :


### Solution :


### Concept of Race Condition
A race condition occurs when multiple threads execute concurrently, and the application fails to validate them properly. In this case:
- The file is temporarily moved to a directory (e.g., `avatars/`) before `FileType` and `Virus` checks.
- There’s a brief window where the file exists and can be executed before validation deletes it.
- Concurrent uploads allow exploitation by accessing the file during this window.

### Code Insight
The vulnerable code likely looks like:
```php
<?php
$target_dir = "avatars/";
$target_file = $target_dir . $_FILES["avatar"]["name"];
move_uploaded_file($_FILES["avatar"]["tmp_name"], $target_file);
if (checkViruses($target_file) && checkFileType($target_file)) {
    echo "File uploaded.";
} else {
    unlink($target_file); // Deleted if invalid
    echo "Error uploading.";
    http_response_code(403);
}
?>

```

- **Vulnerability**: The file is movable and executable before validation, creating a race condition.

## Exploit Steps

### 1. Create PHP Web Shell
Create `shell.php` with:
```php
<?php
echo file_get_contents('/home/carlos/secret');
?>

```

![image](https://github.com/user-attachments/assets/1c2dde98-56a9-4827-a595-45c485ec1739)

The below is get request of shell.php,which we have uploaded in above image we can see.

![image](https://github.com/user-attachments/assets/dbde8bf8-2d68-4c0b-96ea-f3100ff04df6)


### 🔧 Intruder Settings

- **Attack Type:** `Sniper`  
  (We are targeting a single position in the request where the file upload happens.)

- **Payload Type:** `Null Payloads`  
  (Since we don’t need to modify the request content, this allows us to send the same request over and over.)

- **Payload Settings:**  
  - **Start attack** and set it to **continue indefinitely**  
  - This ensures continuous uploading, increasing our chances of hitting the race window.

- **Payload Encoding:**  
  🔲 **Uncheck** the box next to _"URL-encode these characters"_  
  (We want to keep the request exactly as-is without any encoding applied to special characters.)

 Start Both the Requests Simultaneously

And you will notice you will get secret

![image](https://github.com/user-attachments/assets/1e0730b2-039d-4070-aaf4-cfae9bd2e4eb)

Submit the key above and lab will be solved

----
