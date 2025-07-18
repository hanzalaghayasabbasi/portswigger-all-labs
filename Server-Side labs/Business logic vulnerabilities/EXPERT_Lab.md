## Labs Covered

This write-up focuses on the following **EXPERT-level lab** from the PortSwigger Web Security Academy:

- **Bypassing access controls using email address parsing discrepancies**  
  This lab demonstrates how discrepancies in email address parsing between different components of an application can be exploited to bypass access controls.

---

## LAB 1 - Bypassing access controls using email address parsing discrepancies

### Lab Description :


### Solution :

### Identify the registration restriction:

- Navigate to the lab environment provided in the exercise.
- Click on the **Register** button to open the account registration form.
- Use the following email during registration:

  ![image](https://github.com/user-attachments/assets/4b951f0a-1285-4c25-979d-6515e06d4e7f)


Notice that the application blocks the request and displays an error message stating that the email domain must be **ginandjuice.shop**. This indicates the server enforces a **domain check** during registration

![image](https://github.com/user-attachments/assets/9f716ab5-9a40-4b5d-a06d-eeb138e9abba)



### Investigate encoding discrepancies:
Try to register an account with the following email:
`?iso-8859-1?q?=61=62=63?=foo@ginandjuice.shop`
This is the email abcfoo@ginandjuice.shop, with the abc portion encoded using Q encoding, which is part of the "encoded-word" standard.

![image](https://github.com/user-attachments/assets/f3ea9037-2719-4b51-9318-1fc891d50432)

Notice that the registration is blocked with the **error**: "Registration blocked for security reasons."

![image](https://github.com/user-attachments/assets/874874fd-6ec5-4d4f-950a-f06de78f213d)

Try to register an account with the following UTF-8 encoded email:
`=?utf-8?q?=61=62=63?=foo@ginandjuice.shop`

![image](https://github.com/user-attachments/assets/90f13037-623e-401b-ba1f-91b0886d5a51)

Try to register an account with the following UTF-7 encoded email:
`=?utf-7?q?&AGEAYgBj-?=foo@ginandjuice.shop`


![image](https://github.com/user-attachments/assets/c564e3f4-4201-488c-bfdf-3fd0eb3ebc92)


### Email register succesfully with UTF-7 encoding:

Notice that this attempt doesn't trigger an error. This suggests that the server doesn't recognize **UTF-7 encoding** as a security threat. Because **UTF-7** encoding appears to bypass the server's validation, you may be able to use it to craft an attack that tricks the server into sending a confirmation email to your exploit server email address while appearing to still satisfy the ginandjuice.shop domain requirement

![image](https://github.com/user-attachments/assets/b8313172-6b4a-4355-ab54-1fc674ba3e88)

### Exploit the vulnerability using UTF-7:


Payload = `?utf-7?q?hanzala&AEA-exploit-0ac00054036ef89280a82557012f00a4.exploit-server.net&ACA-?=@ginandjuice.shop`

### Decoding the Components:

  **1. UTF-7 Encoding:** 
		○ The AEA- and ACA- parts are used to encode special characters. In this case, they represent the characters @ and spaces.
	**2. Decoded Email:** *
		○ When you decode the entire string, you get: ` attacker@[YOUR-EXPLOIT-SERVER_ID]@ginandjuice.shop`


![image](https://github.com/user-attachments/assets/2c725012-c8c3-4e63-a567-e3385f7f9a89)

Click **Email client**. Notice that you have been sent a registration validation email. This isbecause the encoded email address has passed validation due to the `@ginandjuice.shop` portion at the end, but the email server has interpreted the registration email as **attacker@[YOUR-EXPLOIT-SERVER-ID].**

1 Click the confirmation link to activate the account.

![image](https://github.com/user-attachments/assets/83237f92-1f39-4e3c-94fe-89c15eaf4ab2)


Login after Registration successfully.

![image](https://github.com/user-attachments/assets/155f3fc1-4472-4187-9073-a415139fbc61)

### Gain admin access:
  1. Click **My account** and log in using the details you registered.
  2. Click **Admin panel** to access the list of users

![image](https://github.com/user-attachments/assets/44ba259b-7b6d-4ac7-a568-e48073a255fa)

Delete the carlos user to solve the lab.

![image](https://github.com/user-attachments/assets/14545807-a920-4994-a239-f074aa3eee36)




