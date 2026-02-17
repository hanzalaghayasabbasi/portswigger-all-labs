# Access Control 

## Lab Levels

Jump directly to the lab writeups:

* [APPRENTICE](./APPRENTICE_Lab.md)
* [PRACTITIONER](./PRACTITIONER_Lab.md)

  
## Introduction


Access control is the enforcement of restrictions on what authenticated users are permitted to do. It builds on top of **authentication** (verifying identity) and **session management** (tracking the identity across requests).

Broken access control vulnerabilities are extremely common and often critical, allowing unauthorized users to perform actions or access data outside their intended permissions.

---

## **Types of Access Controls**

### 1. **Vertical Access Control**

* **Definition:** Restricts access based on the **user’s role or clearance level**.
* **Purpose:** Ensures that only higher-level users can perform sensitive actions.
* **Example:**

  * An **admin** can delete user accounts.
  * A **regular user** can only view their own account.
* **Key Concept:** *“Who you are determines what you can do.”*

<p align="center">
  <img src="https://github.com/user-attachments/assets/34fda04b-9451-4504-a752-7838ff740c53" width="400" alt="Vertical Access Control Example">
  <br>
  <em>Figure: Users with higher roles (like Admin) have more permissions than lower roles (like Regular User).</em>
</p>

---

### 2. **Horizontal Access Control**

* **Definition:** Restricts access to **objects specific to the user**, regardless of role.
* **Purpose:** Prevents users with the same role from accessing each other’s data.
* **Example:**

  * Two employees in the same department can’t view each other’s payroll.
  * A student can only see their own grades.
* **Key Concept:** *“What belongs to you stays with you.”*

<p align="center">
  <img src="https://github.com/user-attachments/assets/38aa4848-0361-4057-a5e1-98ce8797dd3f" width="400" alt="Horizontal Access Control Example">
  <br>
  <em>Figure: Users with the same role can only access their own data, not others’ data.</em>
</p>

---

### 3. **Context-Dependent Access Control**

* **Definition:** Access depends on the **state of the application or specific interactions**.
* **Purpose:** Adds dynamic security by considering context like time, location, device, or actions.
* **Example:**

  * Editing is only allowed if the document is **checked out**.
  * Access is restricted when logging in from an **unrecognized device**.
* **Key Concept:** *“Access depends on the situation.”*

<p align="center">
  <img src="https://github.com/user-attachments/assets/32c2fdf1-3410-4a55-a2dd-5f96e401caa0" width="400" alt="Context-Dependent Access Control Example">
  <br>
  <em>Figure: Access granted or denied depending on context, such as device or session state.</em>
</p>


---







## How to Prevent Access Control Vulnerabilities

- Deny access by default to all resources.
- Centralize access control logic.
- Do not rely on client-side controls, obfuscated URLs, or headers.
- Perform server-side authorization checks for every sensitive operation.
- Require explicit access declarations in code.
- Audit and test access controls thoroughly.
- Use a role-based access control (RBAC) system where feasible.

---

## Reference

Original source: [PortSwigger – Access Control](https://portswigger.net/web-security/access-control)

---

