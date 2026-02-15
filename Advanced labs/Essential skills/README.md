
# Essential Skills

## Lab Levels

Jump directly to the lab writeups:

* [PRACTITIONER](./PRACTITIONER_Lab.md)


## Introduction

The Web Security Academy labs are designed to be as realistic as possible, but each lab demonstrates just one variation of a given vulnerability. In real-world testing, it's essential to recognize different manifestations of the same underlying issues and adapt your techniques accordingly.

This section introduces broadly applicable skills to help you transition from lab environments to live targets. It includes practical tips, advanced testing techniques, and guidance on using Burp Suite more effectively during manual testing.

---

## Using Burp Scanner During Manual Testing

Testing certain vulnerabilities—especially those involving numerous injection points—can be tedious and time-consuming. Manual testing alone may lead to missed critical flaws due to time constraints.

To improve efficiency:

- Use Burp Scanner to automate repetitive tasks.
- Let Burp quickly highlight potential vulnerabilities and unusual responses.
- Focus your manual efforts on logic flaws, chaining vulnerabilities, and testing creative edge cases.

Burp Scanner complements human intuition, helping you identify attack vectors more efficiently while maintaining a strong manual testing approach.

---

## Identifying Unknown Vulnerabilities

Unlike the labs where the target vulnerability is known, real-world testing often involves working blind. To identify unknown vulnerabilities:

- Explore all user-controllable inputs: query strings, headers, cookies, request body, etc.
- Watch for clues like error messages, reflected input, or inconsistent behavior.
- Infer potential flaws based on application functionality and business logic.

To practice this skill, use **mystery labs** that hide the vulnerability type entirely. These exercises simulate real-world conditions and help sharpen your intuition and analytical thinking.

---
