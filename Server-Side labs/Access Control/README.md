# Access Control 

## Lab Levels

Jump directly to the lab writeups:

* [APPRENTICE](./APPRENTICE_Lab.md)
* [PRACTITIONER](./PRACTITIONER_Lab.md)

  
## Introduction


Access control is the enforcement of restrictions on what authenticated users are permitted to do. It builds on top of **authentication** (verifying identity) and **session management** (tracking the identity across requests).

Broken access control vulnerabilities are extremely common and often critical, allowing unauthorized users to perform actions or access data outside their intended permissions.

---

## Types of Access Controls

### Vertical Access Control
Restricts access based on user roles.  
**Example:** Admins can delete users, but regular users cannot.

### Horizontal Access Control
Restricts access to objects specific to the user.  
**Example:** A user can see only their account details, not someone else's.

### Context-Dependent Access Control
Restricts access depending on the application’s state or user interaction.  
**Example:** A user cannot modify a cart after placing an order.

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

Explore the labs in this folder:

- `APPRENTICE_Lab.md`
- `PRACTITIONER_Lab.md`

---

