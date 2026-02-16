# Authentication Vulnerabilities

## Lab Levels

Jump directly to the lab writeups:

* [APPRENTICE](./APPRENTICE_Lab.md)
* [PRACTITIONER](./PRACTITIONER_Lab.md)
* [EXPERT](./EXPERT_Lab.md)

  
## Introduction


Authentication vulnerabilities occur when websites implement login and identity verification mechanisms improperly. These issues can allow attackers to gain unauthorized access to user accounts or escalate privileges.

---

## What is Authentication?

Authentication is the process of verifying the identity of a user.

### Three Common Factors:
- **Knowledge**: Something the user knows (e.g., password).
- **Possession**: Something the user has (e.g., mobile device).
- **Inherence**: Something the user is (e.g., biometrics).

---

## Authentication vs Authorization

- **Authentication**: Confirms who the user is.
- **Authorization**: Determines what the authenticated user is allowed to do.

---

## Common Vulnerabilities

### 1. Weak Password Protections
- Lack of brute-force protections
- Use of default credentials

### 2. Broken Authentication Logic
- Skipping or bypassing verification checks

### 3. Password Reset Poisoning
- Manipulating password reset mechanisms to hijack accounts

### 4. Session Management Flaws
- Predictable session IDs
- No session expiration
- No `HttpOnly` or `Secure` cookie flags

### 5. Flawed Multi-Factor Authentication (MFA)
- MFA bypass using fallback or secondary flows

### 6. Third-Party Authentication (OAuth)
- Improper trust between client and identity provider

---

## Real-World Exploitation Scenarios

- Login bypass by modifying logic or parameters
- Brute-force login using username enumeration
- Reset link poisoning to change passwords
- Session hijacking after login
- OAuth misconfigurations to impersonate users

---

## How to Prevent

- Rate-limit login attempts and implement account lockouts
- Use strong, unique passwords and encourage use of password managers
- Implement MFA
- Use secure session cookies (`HttpOnly`, `Secure`, `SameSite`)
- Avoid storing role or access flags in client-controllable parameters
- Ensure all authentication flows are consistent and secure
- Use generic error messages for failed login attempts

---

## Associated Lab Files

- `APPRENTICE_Lab.md`
- `PRACTITIONER_Lab.md`
- `EXPERT_Lab.md`

---

## Learn More

- [PortSwigger Authentication Guide](https://portswigger.net/web-security/authentication)
- [OAuth Authentication Labs](https://portswigger.net/web-security/oauth)
