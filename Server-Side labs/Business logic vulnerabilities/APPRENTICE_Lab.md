## Labs Covered

This write-up focuses on the following **APPRENTICE-level labs** from the PortSwigger Web Security Academy:

* **Excessive trust in client-side controls**
  This lab demonstrates how relying too much on client-side validation allows attackers to bypass security checks and manipulate requests directly.

* **High-level logic vulnerability**
  This lab shows how flaws in business logic can be exploited to achieve unauthorized actions that violate intended workflows.

* **Inconsistent security controls**
  This lab illustrates how varying levels of security controls across different parts of an application can be exploited by attackers to bypass restrictions.

* **Flawed enforcement of business rules**
  This lab demonstrates how poorly enforced business logic can enable attackers to manipulate application behavior for personal gain.

## Authentication Vulnerabilities

Authentication vulnerabilities can allow attackers to gain access to sensitive data and functionality. They also expose additional attack surface for further exploits.

**Authentication** is the process of verifying that a user is who they claim to be.
**Authorization** involves verifying whether a user is allowed to do something.

---

## LAB 1 - Excessive trust in client-side controls

### Lab Description :

![image](https://github.com/user-attachments/assets/936f9d21-114f-424f-862c-18640f0f5f77)

### Solution :

First login as wiener.

### Analyze the application flow -

Click on any product, we can see an **add to cart**  button.

![image](https://github.com/user-attachments/assets/8d7264d0-972b-4f17-9f36-b67f3913b907)

Now 1 item has been added to cart.

![image](https://github.com/user-attachments/assets/e98cf830-0465-4941-9f74-2058e9b4e6b1)

Clicking on the cart button takes us to final  payment page.


![image](https://github.com/user-attachments/assets/98ea3859-3952-4308-ab61-edfb42cbc925)


In the above process, when clicking on **add to cart**, the following *POST* request is sent to */cart


![image](https://github.com/user-attachments/assets/b1eb9df1-580d-4031-92e9-4a26ae4d3a54)


Notice that there is a parameter `price=1337`. We can try modifying the parameter to some other value.

Send the request


![image](https://github.com/user-attachments/assets/bce67cf8-93e3-4cef-b71c-f92163726193)


Lab is solved when we place order

![image](https://github.com/user-attachments/assets/59254eef-84a8-400a-841b-90fcf8cf7107)


---

## LAB 2 - High-level logic vulnerability

### Lab Description :

![image](https://github.com/user-attachments/assets/072d4aff-56d0-49de-a7e7-efd2f5083310)

### Solution :


Log in to the shopping website as wiener.

The price of the leather jacket is **$1337** . We need to find a business logic bug to manipulate the price and buy it.

![image](https://github.com/user-attachments/assets/6091851c-4424-4894-8a9b-63dc8d07faeb)

When clicking on add to cart, the following POST Request is sent with a parameter `quantity=1337` in the request body.

![image](https://github.com/user-attachments/assets/1ddd374e-f6c7-40b6-ae8c-e77997f3c848)

Add another item and view the shopping cart:

![image](https://github.com/user-attachments/assets/bb3cc9a5-f4f4-4f0c-bd28-9565d384b98f)


To exploit the pricing vulnerability, intercept the product addition request using a web proxy tool (such as Burp Suite) and modify the `quantity` parameter to a substantial negative value (e.g., `-145`).

This manipulation causes the server to miscalculate the total price by subtracting the absolute value of the negative quantity multiplied by the unit price from the original total. In the demonstrated scenario, this results in the price being reduced to **$31.40**.

![image](https://github.com/user-attachments/assets/4ba5c544-69f7-4da8-8a19-e984bbcc8a3c)

The total price of the jacket is **$1337** but we were able to buy it just for **$31.40 dollars** by parameter tampering.

Place the order to solve the lab.
![image](https://github.com/user-attachments/assets/e2eabab2-9d5e-464d-9d9f-b86a81c0a45b)


---



## LAB 3 - Inconsistent security controls

### Lab Description :


### Solution :

Access **/admin** page directly:

![image](https://github.com/user-attachments/assets/34e9ed87-66ff-4c0c-9fb0-9b1619951d3c)


It will prompt that only the user **dontwannacry** can access. Admin panel
Register a new user and **change or update the email** to **aa@dontwannacry.com**

![image](https://github.com/user-attachments/assets/ff3550d3-de52-4970-b5e6-324f5d94170e)


Now we are able to view the **/admin** page.

![image](https://github.com/user-attachments/assets/59b981e4-87d4-4443-9b26-78fbd8d4b94d)


Delete the user carlos to solve the lab.

![image](https://github.com/user-attachments/assets/edc95886-0d62-44db-9689-b911b82381a0)

---

## LAB 4 - Flawed enforcement of business rules


## Lab Description :

![image](https://github.com/user-attachments/assets/fadee759-53fd-46ac-90f3-f6290ccf0e77)



## Solution :

When the website loads, we see a **message from the developers** indicating that:

> *"New customers can avail additional discounts."*

This implies the site may offer **special pricing logic or promotions** to first-time users, which may be exploitable if not securely implemented.

![image](https://github.com/user-attachments/assets/079ede92-6267-4ada-9cc2-770fb4763f25)


- Navigate to the **shopping page** and add the **Leather Jacket** to the cart.

## 💸 Observation

- Apply the available **promo code** during checkout.
- A **$55 discount** is successfully applied to the item price.

> ✅ The promo code is functioning correctly and reduces the purchase total by **$55**.


![image](https://github.com/user-attachments/assets/176efda5-2a95-4ea4-9eee-d96705740764)


At the bottom of the shopping page we have this signup feature .

![image](https://github.com/user-attachments/assets/16b5e617-cd8d-4a59-b327-9b793432e021)


Signing up for newsletter gives us another $50 dollar discount.

![image](https://github.com/user-attachments/assets/18853eec-1ed7-4853-984e-5f78da6ca077)


Clicking on place-order button ,the order is placed sucessfully.

### 🔍 Flawed Logic Analysis

After analyzing the website’s features, we assess the application from an attacker's perspective and identify potential logical flaws that could be exploited.

#### 🧠 Possible Attack Vectors

1. Attempt to apply the **same coupon code multiple times** until the product price is reduced significantly.
2. Try **alternating between different coupon codes** (e.g., promo code and newsletter code) to repeatedly apply discounts.

---

#### 🧪 Case 1: Reapplying the Same Coupon Code

- When we try to apply the **same promo code repeatedly**, the application displays the following message:

  > *Coupon already applied.*

- This indicates that the application **prevents duplicate use of the same coupon**, likely through a simple coupon ID check.


![image](https://github.com/user-attachments/assets/deb36c13-a566-4a9b-b9bd-2ce1893a2a78)


#### 🧪 Case 2: Alternating Coupon Codes to Stack Discounts

- When we alternate between the **promo code** and the **newsletter discount** repeatedly (e.g., promo → newsletter → promo → newsletter), the system fails to enforce a proper cumulative discount check.

- Each coupon is accepted **again** despite previously being applied in a different order.

![image](https://github.com/user-attachments/assets/50119965-01e4-4534-baeb-81fca11c1bed)


Place the order to solve the lab.

![image](https://github.com/user-attachments/assets/745e1885-9dd3-42c1-ab6f-9353c63f318d)


