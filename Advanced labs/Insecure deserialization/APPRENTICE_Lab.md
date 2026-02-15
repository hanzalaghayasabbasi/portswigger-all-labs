## Labs Covered

This write-up focuses on the following **APPRENTICE-level lab** from the PortSwigger Web Security Academy related to **Insecure Deserialization**:

**1 Modifying serialized objects**  
<blockquote>
This lab demonstrates how attackers can tamper with serialized data structures to manipulate application logic and potentially gain unauthorized access.
</blockquote>

---

### LAB 1 - Modifying serialized objects

### Lab Description

<img width="918" height="348" alt="image" src="https://github.com/user-attachments/assets/6e678e78-1e3d-44d5-a120-4a697e38490b" />

### Solution

Before login I Inspect cookie but there is no value is set for it:


<img width="1894" height="500" alt="image" src="https://github.com/user-attachments/assets/9c25b5f2-622c-4e9b-bf95-69a5e883a949" />


After I  have login I get cookies


<img width="1895" height="517" alt="image" src="https://github.com/user-attachments/assets/6a7c6222-e9ae-4a3b-a1ff-056fb26c71aa" />


Now I have copy he cookie first url decode it and then  **base64** decode it and get the  serialized data from cookie.

<img width="1914" height="699" alt="image" src="https://github.com/user-attachments/assets/d4a91bf3-7057-43e8-86ae-dbaff8903b6e" />




Now I change 0 **to** 1,So in boolean 0 false and 1 true and base64 encode the text

<img width="1915" height="426" alt="image" src="https://github.com/user-attachments/assets/74732048-5465-4430-97e5-89b676e3b7d1" />



Now copy above base **64** and paste it in cookie then send request that tell us you have to navigate to `/admin` to goto admin panel


<img width="1891" height="721" alt="image" src="https://github.com/user-attachments/assets/7d57d37c-46c2-4d35-a261-a53c16472663" />



Navigate to **admin panel**.Now to solve lab we have to delete carlos we have delete carlos and lab is solved

<img width="1898" height="783" alt="image" src="https://github.com/user-attachments/assets/5d4c2092-1641-42c1-b009-af419501d6bf" />

<img width="1250" height="738" alt="image" src="https://github.com/user-attachments/assets/20a98f9d-f533-42ed-ba5b-595045413636" />



Follow redirection and now we can see no carlos user in reponse and lab is solved

<img width="1732" height="718" alt="image" src="https://github.com/user-attachments/assets/af55f80f-3bca-4fe7-9e3f-de8a2ce7863c" />


---


