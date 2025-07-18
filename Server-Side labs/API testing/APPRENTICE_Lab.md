## Lab Covered

This write-up focuses on the following **APPRENTICE-level lab** from the PortSwigger Web Security Academy:

- **Exploiting an API endpoint using documentation**

This lab demonstrates how attackers can take advantage of publicly available API documentation to uncover and exploit sensitive endpoints. It emphasizes the importance of not exposing functionality that should remain private.

---

## LAB 1 - Exploiting an API endpoint using documentation

### Lab Description :
![image](https://github.com/user-attachments/assets/c9f9e4d3-a238-4d94-9de6-377e8475cfb6)



### Solution :

Login as Wiener with the provided credentials - `wiener:peter`.

![image](https://github.com/user-attachments/assets/72588326-0da7-469f-afd5-e4f66150378b)

Now when we change the email of wiener, the browser sends the folowing `PATCH` request to `/api/user/wiener`

![image](https://github.com/user-attachments/assets/37da9e9c-e640-44d6-b01f-c0ac9a3580dc)

So we remove **wiener** form request to see what will happen and we can see below it is giving us Malformed url error

![image](https://github.com/user-attachments/assets/c6fd791c-b9da-4bb6-b3f2-d8974d11c22c)

If we remove **user/wiener** and send the request, the server responds with a `302` redirect. Following the redirect leads us to the REST API documentation.

![image](https://github.com/user-attachments/assets/3f2fe26b-d72b-4b4a-b218-8b59b62e3450)

Now we can delete the user carlos by sending a `DELETE` request to `/api/user/carlos`.

![image](https://github.com/user-attachments/assets/4daa1b26-f3af-4e6c-97f8-39071d344248)

Now we have deleted carlos's account & thus solved the lab.

![image](https://github.com/user-attachments/assets/874fc537-7fdd-46c6-9063-7eaaff4c732d)
