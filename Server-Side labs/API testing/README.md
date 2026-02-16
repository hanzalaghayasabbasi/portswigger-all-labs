# API Testing 

## Lab Levels

Jump directly to the lab writeups:

* [APPRENTICE](./APPRENTICE_Lab.md)
* [PRACTITIONER](./PRACTITIONER_Lab.md)
* [EXPERT](./EXPERT_Lab.md)

  
## Introduction


APIs (Application Programming Interfaces) enable systems and applications to communicate and share data. Due to their central role in dynamic websites, vulnerabilities in APIs can affect the confidentiality, integrity, and availability of core services.

This section focuses on identifying and exploiting vulnerabilities in RESTful and JSON-based APIs, including classic bugs like SQL injection and server-side parameter pollution (SSPP) in internal APIs.

---

## Why API Testing Matters

Modern web applications heavily rely on APIs. Even if an API isn't directly exposed on the frontend, it may still process sensitive operations. Learning to test these hidden endpoints can help uncover deep flaws in application logic or access control.

---

## Key Concepts

### API Reconnaissance

- Identify API endpoints by analyzing frontend requests and using tools like Burp Scanner.
- Examine:
  - Required and optional parameters
  - Supported HTTP methods (e.g., GET, POST, PUT, DELETE)
  - Accepted content types (e.g., application/json)
  - Authentication methods and rate limits

Example endpoint:
```

/api/books/mystery

```
This might return a filtered list of mystery books from a library.

---

### API Documentation

- Look for public or internal documentation (e.g., Swagger, OpenAPI, Postman collections).
- Fuzz common documentation paths such as:

<img width="306" height="112" alt="image" src="https://github.com/user-attachments/assets/c339635d-0771-452a-ba1a-acf4cac32648" />


If you identify an endpoint for a resource, make sure to investigate the base path. For example, if you identify the resource endpoint `/api/swagger/v1/users/123`, then you should investigate the following paths.

<img width="255" height="127" alt="image" src="https://github.com/user-attachments/assets/9dce0628-e87e-4166-9a47-dbb10a86cf5d" />


- Use both human-readable and machine-readable formats to explore the API’s functionality.

---

## Preventing Vulnerabilities in APIs

To avoid vulnerabilities, developers should:

- Restrict access to documentation unless intended to be public
- Keep documentation accurate and updated
- Whitelist allowed HTTP methods
- Validate all inputs and enforce correct content types
- Avoid exposing detailed error messages
- Apply all protections to every version of the API, not just production

---

## Reference

Original source: [PortSwigger – API Testing](https://portswigger.net/web-security/api-testing)

---

