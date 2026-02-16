# Race Conditions

## Lab Levels

Jump directly to the lab writeups:

* [APPRENTICE](./APPRENTICE_Lab.md)
* [PRACTITIONER](./PRACTITIONER_Lab.md)
* [EXPERT](./EXPERT_Lab.md)

  
## Introduction

Race conditions are vulnerabilities that occur when multiple processes access and modify shared data concurrently without proper handling. Attackers exploit the tiny timing window where the application behaves unpredictably, leading to unintended outcomes.

---

## What Is a Race Condition?

A race condition happens when:

1. A system performs checks and then acts based on those checks.
2. Multiple requests are sent in parallel, hitting the system in between the check and the action.
3. The system makes conflicting changes due to inadequate synchronization.

This time gap is called the **race window**, and attackers can exploit it with well-timed requests.

---

## Real-World Example: Reusing a Discount Code

Consider this checkout flow:

1. Check if the discount code is unused.
2. Apply the discount.
3. Update the database to mark the code as used.

If two requests are sent in parallel before step 3 completes, both may succeed—resulting in the same code being used multiple times. This is a classic race condition.

---

## Common Exploitable Scenarios

Race conditions can allow attackers to:

- Redeem gift cards more than once
- Bypass usage limits (e.g., CAPTCHAs, discount codes)
- Submit duplicate votes or reviews
- Make repeated money transfers despite insufficient balance
- Abuse poorly enforced rate limits

These are often categorized as **Time-of-Check to Time-of-Use (TOCTOU)** flaws.

---

## Detecting and Exploiting Race Conditions

### Manual Discovery Steps

1. Identify endpoints with single-use or rate-limited functionality.
2. Observe if these endpoints perform sequential checks before actions.
3. Attempt to trigger multiple parallel requests to the same endpoint.

### Tooling Support: Burp Suite

**Burp Repeater (v2023.9+)** provides two key techniques:

- **Last-byte synchronization (HTTP/1)**: Ensures multiple requests are sent at the same final byte.
- **Single-packet attack (HTTP/2)**: Sends up to 30 requests simultaneously in a single TCP packet to eliminate network jitter.

These capabilities improve the timing accuracy needed to trigger a collision.

---

## Race Condition Lab Scenarios

Labs often simulate real-world logic flaws such as:

- Submitting the same form repeatedly
- Redeeming the same gift card
- Submitting multiple password reset requests
- Voting multiple times
- Reusing single-use API tokens

These help practice both identification and exploitation.

---


## Learn More

- PortSwigger Whitepaper: *Smashing the State Machine – The True Potential of Web Race Conditions* (Black Hat USA 2023)

