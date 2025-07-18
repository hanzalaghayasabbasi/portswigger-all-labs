## Labs Covered

This write-up focuses on the following **APPRENTICE-level labs** from the PortSwigger Web Security Academy:

- **Remote code execution via web shell upload**  
  This lab demonstrates how an attacker can upload a malicious web shell by bypassing insufficient file upload validation, resulting in remote code execution on the server.

- **Web shell upload via Content-Type restriction bypass**  
  This lab shows how attackers can bypass file upload restrictions by manipulating the Content-Type header, allowing them to upload web shells and achieve remote code execution.

---

## LAB 1 - Remote code execution via web shell upload

### Lab Description :

![image](https://github.com/user-attachments/assets/bcb38139-19e2-4e0b-a809-763fd27cfca6)


### Solution :

Click on any of the blog posts. We can see that we have an option to upload files.

![image](https://github.com/user-attachments/assets/e6aff156-fdb8-4e49-a828-173cb601f570)


Similarly login as wiener & we can see that there is an upload functionality here also.
![image](https://github.com/user-attachments/assets/5ae8668e-0f95-41b1-833e-2a4cf38d956d)


After the image has been uploaded, open Burp Suite and go to the **Proxy > HTTP History** tab. This area logs all HTTP requests and responses that pass through the proxy. Look through the list and identify the `POST` request associated with your file upload.

Once located, analyze the structure of this `POST` request. Pay particular attention to the `Content-Type` header, which should reflect the file’s MIME type (e.g., `image/png`). Also, examine the request or server response for any indication of the **upload directory**—this is the location where the server stores uploaded files. Knowing this directory is important, as it can be useful in further stages of testing or exploitation.

![image](https://github.com/user-attachments/assets/46575e43-a78a-41d8-8952-139be7b1dd3b)

Now sending request to repeater of the image above we uploaded

![image](https://github.com/user-attachments/assets/0292a8c3-e3d4-4614-b565-2769573031ab)

Now removing all the content of png and  and changing file extension to **.php** we have then  successfully  upload file of php with the contents ` <?php echo file_get_contents('/home/carlos/file.php'); ?>`

![image](https://github.com/user-attachments/assets/63df424c-42a3-4995-b8e5-a35416b37354)

The response indicates that the file upload of **myexploit.php** was successful.


Now getting the file we have uploaded give us secret.

![image](https://github.com/user-attachments/assets/40eb56d1-f1c6-4576-8a20-4448dad3a7f4)

Submit the value to solve the lab.

![image](https://github.com/user-attachments/assets/c337dace-dc97-43a0-b85f-d161ae9bd12c)


---

## LAB 2 - Web shell upload via Content-Type restriction bypass

### Lab Description :

![image](https://github.com/user-attachments/assets/7be46a0b-3ba7-44a1-90b6-e82977556a23)


### Solution :

To begin with the lab, we need to first access it and log in using the provided credentials. Once logged in, enable Burp Suite’s proxy to capture and analyze the traffic between the browser and the server.

After enabling the proxy, upload any simple image file (e.g., `sample.png`) using the image upload function on the lab interface. Once the upload is complete, navigate to the **Proxy > HTTP History** tab in Burp Suite to review the captured requests.

In the HTTP history, you’ll notice two important requests:
1. A **POST** request, which contains the actual upload of the `sample.png` file to the server.
2. A **GET** request, which reveals the location or path of the uploaded image on the server.

These two requests are crucial for understanding how the application handles file uploads and will assist in identifying the web shell location in the case of a successful upload exploit.

![image](https://github.com/user-attachments/assets/431a11e7-5035-4146-9f21-1ae49caedc2c)

We will send both of these requests to the repeater tab. We will name the post-based request **“UploadImage”** and the get-based request **“ShowImage”**

![image](https://github.com/user-attachments/assets/d477edb2-cedf-4960-8c18-1fd6b2cbd1e2)

Firstly, I will modify the name `filename = 'sample.png'` to `filename = 'myexploit.php'`.

![image](https://github.com/user-attachments/assets/3a0fdf42-3bfc-4109-b89d-932a6ffc0617)

After that, I will remove all the raw data or image content present under the `Content-Type` section of the request body. This binary data represents the actual contents of the uploaded image and is not needed for our payload.

Once the raw data is removed, I will insert my PHP payload as shown below:

```php
<?php echo file_get_contents('/home/carlos/secret'); ?>
```
This payload is crafted to read and display the contents of the **/home/carlos/secret** file, which is the main objective of the lab. Successfully uploading and executing this PHP file will confirm that the vulnerability has been exploited.

![image](https://github.com/user-attachments/assets/3e4297c6-3d30-47de-b095-40b57d757a27)


After submitting the request, I will simply switch to my second tab which is 

**ShowImage**.

Send request and we will get secret

![image](https://github.com/user-attachments/assets/2e35655b-a5dc-4262-9166-9e69447ba38a)


Submit the key to solve the lab.

![image](https://github.com/user-attachments/assets/786f0ef3-7fd3-4075-ae32-fcfd803ad9bd)

