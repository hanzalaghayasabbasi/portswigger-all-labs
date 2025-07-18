## Labs Covered

This write-up focuses on the following **APPRENTICE-level lab** from the PortSwigger Web Security Academy:

**Limit overrun race conditions**  
This lab demonstrates how attackers can exploit a race condition to exceed server-imposed limits by sending multiple simultaneous requests before the limit is properly enforced.

---

### LAB 1 - Limit overrun race conditions

### Lab Description

![image](https://github.com/user-attachments/assets/dcbed4fe-4bca-4f0e-b45d-7be85c31de00)


### Race Conditions Overview

A **race condition** is a flaw that produces an unexpected result when the timing of actions impacts other actions. This typically occurs in multithreaded applications where operations act concurrently on shared data.

Race conditions are difficult to test for due to their timing-dependent nature. The critical period during which a collision may occur is called the **race window** — often lasting just milliseconds.

> ⚠️ **Note**: The **Race Conditions** lab requires **Burp Suite 2023.9** or a later version.

---

### Exploiting Race Conditions

#### Limit Overrun Race Conditions

The most common race condition allows users to **exceed application-imposed limits**, such as single-use promo codes or transaction limits.

For example, an online store might perform the following steps when applying a discount code:

1. Check if the code has already been used.
2. Apply the discount.
3. Mark the code as used in the database.

If you later attempt to reuse this code, the initial checks performed at the start of the process should prevent you from doing this:


![image](https://github.com/user-attachments/assets/89cb7507-16e3-4a85-beed-725161f0dbda)

Now consider what would happen if a user who has never applied this discount code before tried to apply it twice at almost exactly the same time:

![image](https://github.com/user-attachments/assets/ba8b01ff-10a0-482c-8f54-485016ae412a)


---

### Exploiting Race Conditions Using Burp Repeater

#### Steps:

1. **Identify** a single-use or rate-limited endpoint with useful functionality (e.g., discounts, reward redemptions, password resets).
2. **Send multiple concurrent requests** to the endpoint as close in time as possible to attempt to **exploit the race window**.


---

#### Challenges:

The main challenge is **timing**. You must hit the race window precisely — a tiny overlap in milliseconds is enough.

Even perfectly-timed requests may be processed in unpredictable order due to factors like:

- Server load
- Network jitter
- Request queuing

![image](https://github.com/user-attachments/assets/c3183476-c892-4536-9037-dea74b763078)

---

### Burp Suite 2023.9+: Parallel Requests

With **Burp Suite 2023.9**, **Repeater** now supports sending multiple requests **in parallel**, reducing the impact of timing inconsistencies.

#### Features:

- **Parallel request groups**: Fire off a batch of requests at once.
- **Single-packet attacks**: Send 20–30 requests in a single TCP packet to **neutralize network jitter**.

These features significantly improve your ability to **detect and exploit race conditions**, including advanced multi-step logic flaws.
![image](https://github.com/user-attachments/assets/97876746-73a6-4607-8e3e-75ce28447188)



### Solution:



# Lab Solution: Exploiting Race Condition for Coupon Discount

1. **Login to the Application**
   - Log in using the provided credentials: `wiener:peter`.

![image](https://github.com/user-attachments/assets/0a155850-3997-4cf3-aceb-d12178bfec27)


2. **View Promo Code**
   - After logging in, the page will display a promo code for a discount.
     
   ![image](https://github.com/user-attachments/assets/c084a53f-f6de-4ddb-936f-3b26c37539a1)



3. **Add Item to Cart**
   - Add an umbrella to the cart.
   
    ![image](https://github.com/user-attachments/assets/790a909d-5a3b-4e81-bc17-95dbdd4d97a8)



4. **Apply Coupon**
   - Apply the coupon to receive a 20% discount.
  
    ![image](https://github.com/user-attachments/assets/ae3850f9-1322-4145-bfb2-15a80c71c71c)



5. **Test Coupon Restriction**
   - Attempt to apply the coupon a second time; this will result in an error indicating the coupon can only be used once.
  
   - ![image](https://github.com/user-attachments/assets/2ba4fe8d-e98d-4f46-9307-ab3d2c79fb0d)


6. **Send Coupon Request to Repeater**
   - Intercept the coupon application request and send it to Burp Suite Repeater for analysis.

  ![image](https://github.com/user-attachments/assets/cd48f5ad-e6aa-474a-abb9-df224b8badb9)

7. **Apply Race Condition**
   - Remove the coupon from the cart to reset its state for the race condition exploit.
  
   - ![image](https://github.com/user-attachments/assets/39f33008-81db-497e-8824-2d513d65367e)


8. **Exploit Using Burp Intruder (Method 1)**
   - Send the coupon request to Burp Intruder.

     ![image](https://github.com/user-attachments/assets/3fc7a74a-a9b7-4471-99a7-2150863de5b7)

   - Configure Intruder to use null payloads (e.g., set to 30 payloads) to repeat the coupon request multiple times concurrently.

     ![image](https://github.com/user-attachments/assets/e707bfc7-4e9d-4ede-92e0-444b4dbf2f9b)

   - Run the attack; multiple requests will apply the coupon before the server marks it as used.
  
     ![image](https://github.com/user-attachments/assets/943b455d-fe98-432a-89fe-abdd0a4fa71d)

  

   - Refresh the cart page to confirm the discount exceeds 20%.

      ![image](https://github.com/user-attachments/assets/a58d5598-ae02-4f01-a786-059d48d6eda5)


9. **Exploit Using Parallel Requests (Method 2)**
   - Add a leather jacket to the cart.

      ![image](https://github.com/user-attachments/assets/af9d127d-3a18-4c83-aa41-55641f71514b)


   - Apply the coupon to the leather jacket and intercept the request.
   -  Remove the coupon to reset its state.
   
     ![image](https://github.com/user-attachments/assets/ebde939f-ea52-48d9-86a9-88bee10e70b4)

    - Send the request to Repeater and create a tab group.
     ![image](https://github.com/user-attachments/assets/31474040-f500-4895-bc38-16b13e57d085)

   - Duplicate the coupon request 50 times in Repeater (use shortcut: Ctrl+R).

     ![image](https://github.com/user-attachments/assets/73f379fd-49d6-4a8d-82af-d527d8d16b77)

   - Send the tab group requests in parallel.
  
     ![image](https://github.com/user-attachments/assets/14a7520e-124b-4e56-a0de-86e01ba11d93)

   - Refresh the cart page to confirm the discount is greater than 20%.
  
     ![image](https://github.com/user-attachments/assets/1cf3e6df-1954-482a-8ffd-41cd1d896c73)

10. **Place Order**
    - With the increased discount applied, place the order for the leather jacket.
   
      ![image](https://github.com/user-attachments/assets/d3cc34c6-7fc2-4bf8-9d84-db83e386f670)


11. **Lab Completion**
    - The lab is solved once the leather jacket is successfully purchased with the discount.
    
      ![image](https://github.com/user-attachments/assets/f883565e-5117-4d40-a8df-849a30d58c4e)

