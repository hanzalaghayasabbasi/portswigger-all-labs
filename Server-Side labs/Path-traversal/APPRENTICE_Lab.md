## Labs Covered

This write-up focuses on the following **APPRENTICE-level lab** from the PortSwigger Web Security Academy:

**1 File path traversal, simple case**  
   <blockquote>
  This lab demonstrates how attackers can exploit insufficient validation of user-supplied file paths to read arbitrary files on the server.
   </blockquote>

---

## LAB 1 - File path traversal, simple case

### Lab Description :

![image](https://github.com/user-attachments/assets/3c6f90c6-9464-453d-b89d-8a7d1257e018)


### Overview:

![image](https://github.com/user-attachments/assets/688a4188-0bba-47c7-b804-8c26eecc9847)

### Solution :

When we load the page, we get several items with its images, a request is being made to retreive the images from the server.

The captured request looks like ,

![image](https://github.com/user-attachments/assets/184357b1-b5e5-4d86-8d55-1a04800c4e9f)

To retrieve /etc/passwd:

``` GET /image?filename=../../../etc/passwd ```

![image](https://github.com/user-attachments/assets/452b5aa8-e0b7-4395-8a3f-1fda00402e51)

And lab is solved

![image](https://github.com/user-attachments/assets/d26ab1b1-da23-4d4f-8839-b20ff9ccaa34)

