## Labs Covered

This write-up focuses on the following **APPRENTICE-level lab** from the PortSwigger Web Security Academy:

- **OS command injection, simple case**  
  This lab demonstrates how an attacker can exploit unsanitized user input that is directly passed to system commands, allowing them to execute arbitrary OS commands on the server.

---

## LAB 1 - OS command injection, simple case

### Lab Description :

![image](https://github.com/user-attachments/assets/318f2438-22bf-49d7-ac26-5081cbb6cb57)

### Overview :
![image](https://github.com/user-attachments/assets/af6861f8-cdf1-4d6f-a893-81665a17e62a)


### Solution :

We have  check stock feature on the website.

![image](https://github.com/user-attachments/assets/d010542c-49ae-42c2-8294-b6317a9db455)

Intercept the above request and do out of band interaction through collabarator

![image](https://github.com/user-attachments/assets/015e07fa-6cb2-4e33-9c37-38b57db5d628)

We can see that we get response from above collabarator to burp

![image](https://github.com/user-attachments/assets/55c6db8a-cb74-4b62-b1c5-389c38a2c832)


If we try with  **productId** we will get errror

![image](https://github.com/user-attachments/assets/60de8912-1a4e-4e78-b049-96a97d84980c)

Now we will try to exceute **command of** `whoami` from **storeId** and lab will be solved

![image](https://github.com/user-attachments/assets/e6103ca8-8398-4d75-8f86-4a7c4f9b1797)
