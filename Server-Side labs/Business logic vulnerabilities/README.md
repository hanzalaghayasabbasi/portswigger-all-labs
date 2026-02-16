# Business Logic Vulnerabilities

## Lab Levels

Jump directly to the lab writeups:

* [APPRENTICE](./APPRENTICE_Lab.md)
* [PRACTITIONER](./PRACTITIONER_Lab.md)
* [EXPERT](./EXPERT_Lab.md)

  
## Introduction


Business logic vulnerabilities are flaws in the design or implementation of application workflows that attackers can exploit to elicit unintended behavior. These are often due to flawed assumptions about how users will interact with the system.

---

## What Are Business Logic Vulnerabilities?

- Logic flaws allow attackers to manipulate legitimate features for malicious outcomes.
- They result from developers not anticipating abnormal or malicious user behaviors.
- Business logic is the set of rules that govern how an application behaves; vulnerabilities arise when these rules can be bypassed or abused.

---

## Why Are They Dangerous?

- They are often missed by automated scanners.
- They are context-dependent and may require business understanding to find or exploit.
- When exploited, they can allow attackers to:
  - Skip purchasing workflows
  - Modify critical parameters
  - Bypass authentication or authorization
  - Perform financial fraud or data manipulation

---

## How Do They Arise?

- Flawed assumptions (e.g., users only submit requests through the browser)
- Incomplete server-side validation
- Overreliance on client-side controls
- Complexity and miscommunication within development teams
- Lack of holistic understanding of application behavior

---

## Real-World Examples

- Skipping payment confirmation step to get free products
- Using negative quantities to increase wallet balance
- Replaying or modifying API calls to change order pricing
- Manipulating workflow steps out of intended order
- Exploiting inconsistent state between client and server

---

## What Is the Impact?

- Financial loss (fraud, theft)
- Account takeover or privilege escalation
- Unauthorized access to sensitive functionality
- Abuse of business processes to gain competitive or malicious advantage
- Reputational damage or customer data exposure

---

## How to Prevent

- Apply strict server-side validation for every input
- Do not trust client-side logic
- Treat every request as potentially malicious
- Define and enforce clear workflows
- Use threat modeling to identify unexpected interactions
- Document assumptions and business rules for each feature

---

## Associated Lab Files

- `APPRENTICE_Lab.md`
- `PRACTITIONER_Lab.md`
- `EXPERT_Lab.md`

---

## Learn More

- [PortSwigger Business Logic Vulnerabilities](https://portswigger.net/web-security/logic-flaws)
