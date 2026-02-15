# HTTP Request Smuggling Overview

## Lab Levels

Jump directly to the lab writeups:


* [PRACTITIONER](./PRACTITIONER_Lab.md)
* [EXPERT](./EXPERT_Lab.md)


## Introduction

## What is HTTP Request Smuggling?

HTTP request smuggling is a web security vulnerability that allows attackers to manipulate HTTP requests in a way that exploits differences in how front-end and back-end servers interpret them. By sending ambiguous requests, attackers can disrupt the normal processing of request sequences, potentially leading to serious consequences such as bypassing security controls, accessing sensitive data, or interfering with other users’ interactions. This issue is particularly prevalent in HTTP/1 setups, though HTTP/2 systems can also be affected when downgraded to HTTP/1 for back-end communication. It’s a critical concern because it undermines the integrity of web application traffic, making it a powerful tool for attackers.

<img width="1006" height="503" alt="image" src="https://github.com/user-attachments/assets/6c3d1ec5-b7c7-4c61-8dd0-7ab593dc1b8e" />

---

# What Happens in an HTTP Request Smuggling Attack?

Modern web applications often rely on a chain of servers to process incoming requests. A **front-end server**—like a load balancer or reverse proxy—receives requests from users and forwards them to a **back-end server** for processing. To improve efficiency, the front-end typically sends multiple requests over a single persistent connection, requiring both servers to agree on where one request ends and the next begins.

In an HTTP request smuggling attack, the attacker crafts a request that is interpreted differently by the two servers:

- The **front-end server** might see it as a single, complete request.
- The **back-end server** might split it into multiple requests or misalign the boundaries.

- <img width="951" height="515" alt="image" src="https://github.com/user-attachments/assets/6dfc6043-ff34-4050-89c5-eac8b76b96df" />


For example, an attacker could "smuggle" a portion of their request past the front-end server, attaching it to the next legitimate request processed by the back-end. This desynchronization can enable:

- **Interfering with other users’ requests**: The smuggled data could alter or hijack another user’s request.
- **Bypassing security controls**: Access to restricted areas (e.g., `/admin`) could be gained.
- **Extracting sensitive data**: The attacker might trigger unintended responses containing confidential information.

The root of the problem lies in the servers’ disagreement on request boundaries, which attackers exploit to manipulate the flow of traffic.

---

# How Do HTTP Request Smuggling Vulnerabilities Arise?

HTTP request smuggling vulnerabilities stem from the HTTP/1 specification, which provides two methods to define the length of a request’s body:

1. **Content-Length Header**  
   Specifies the exact length of the body in bytes.  
   **Example:**
   ```
   POST / HTTP/1.1
   Host: example.com
   Content-Length: 11
   Hello World
   ```
   Here, the body (`Hello World`) is 11 bytes long.

2. **Transfer-Encoding Header**  
   Uses chunked encoding to send the body in segments, with each chunk’s size given in hexadecimal, ending with a zero chunk.  
   **Example:**
   ```
   POST / HTTP/1.1
   Host: example.com
   Transfer-Encoding: chunked
   5
   Hello
   6
   World!
   0
   ```
   The body is sent in two chunks (`Hello` and `World!`), terminated by `0`.

According to the HTTP/1 standard, if both `Content-Length` and `Transfer-Encoding` headers are present, `Transfer-Encoding` takes precedence, and `Content-Length` is ignored. However, problems arise in chained server setups due to inconsistent handling:

- Some servers may not fully support `Transfer-Encoding` for incoming requests.
- Others might be tricked by obfuscated headers (e.g., `Transfer-Encoding: xchunked`).

When the front-end and back-end servers process these headers differently—one using `Content-Length` and the other `Transfer-Encoding`—they disagree on where the request ends, creating an opportunity for smuggling.

**HTTP/2 Context**: HTTP/2 uses a frame-based mechanism to define request lengths, making it resistant to classic smuggling when implemented end-to-end. However, if an HTTP/2 front-end downgrades requests to HTTP/1 for back-end communication, the same vulnerabilities can resurface.

---

# Types of HTTP Request Smuggling Attacks

HTTP request smuggling attacks exploit discrepancies in how front-end and back-end servers interpret the `Content-Length` and `Transfer-Encoding` headers. There are three primary types:

### 1. **CL.TE (Content-Length to Transfer-Encoding)**
- **Description**: The front-end server relies on `Content-Length` to define the request length, while the back-end server uses `Transfer-Encoding`.
- **Mechanism**: The attacker includes both headers in a request. The front-end processes a fixed-length body, while the back-end interprets it as chunked, treating any extra data as a separate request.
- **Example:**
  ```
  POST / HTTP/1.1
  Host: vulnerable-website.com
  Content-Length: 13
  Transfer-Encoding: chunked
  0
  SMUGGLED
  ```
  - **Front-end**: Forwards a 13-byte body (up to `SMUGGLED`).
  - **Back-end**: Ends the request at the `0` chunk, processing `SMUGGLED` as a new request.

### 2. **TE.CL (Transfer-Encoding to Content-Length)**
- **Description**: The front-end server processes `Transfer-Encoding`, while the back-end server uses `Content-Length`.
- **Mechanism**: The attacker sends a chunked request with a small `Content-Length`. The front-end handles the full chunked body, but the back-end stops at the `Content-Length` value, leaving leftover data for the next request.
- **Example:**
  ```
  POST / HTTP/1.1
  Host: vulnerable-website.com
  Content-Length: 3
  Transfer-Encoding: chunked
  8
  SMUGGLED
  0
  ```
  - **Front-end**: Processes the entire chunked body.
  - **Back-end**: Stops after 3 bytes, treating `SMUGGLED` as part of the next request.

### 3. **TE.TE (Transfer-Encoding to Transfer-Encoding)**
- **Description**: Both servers support `Transfer-Encoding`, but the attacker uses obfuscation to trick one server into ignoring it.
- **Mechanism**: Techniques like adding extra spaces or altering capitalization (e.g., `Transfer-Encoding: chunked `) cause a parsing mismatch, leading to desynchronized boundaries.
- **Example**: Obfuscation varies, such as a trailing space in the header, causing one server to overlook it.

---

# How to Perform an HTTP Request Smuggling Attack

Attackers perform HTTP request smuggling by crafting requests that exploit mismatches in header processing. Here’s how the three attack types are executed:

1. **CL.TE (Content-Length to Transfer-Encoding)**  
   - **Setup**: Front-end uses `Content-Length`, back-end uses `Transfer-Encoding`.  
   - **Execution**: The request includes both headers, with `Content-Length` set to a value shorter than the chunked body.  
   - **Example:**
     ```
     POST / HTTP/1.1
     Host: vulnerable-website.com
     Content-Length: 13
     Transfer-Encoding: chunked
     0
     SMUGGLED
     ```
     - **Front-end**: Sees a 13-byte request.  
     - **Back-end**: Ends at the `0` chunk, treating `SMUGGLED` as a new request.

2. **TE.CL (Transfer-Encoding to Content-Length)**  
   - **Setup**: Front-end uses `Transfer-Encoding`, back-end uses `Content-Length`.  
   - **Execution**: A chunked request includes a small `Content-Length`.  
   - **Example:**
     ```
     POST / HTTP/1.1
     Host: vulnerable-website.com
     Content-Length: 3
     Transfer-Encoding: chunked
     8
     SMUGGLED
     0
     ```
     - **Front-end**: Processes all chunks.  
     - **Back-end**: Stops after 3 bytes, smuggling `SMUGGLED`.

3. **TE.TE (Transfer-Encoding to Transfer-Encoding)**  
   - **Setup**: Both servers support `Transfer-Encoding`, but one is tricked by obfuscation.  
   - **Execution**: The attacker manipulates the header (e.g., `Transfer-Encoding: chunked `) to exploit parsing differences.

**Conditions for Success**:
- The connection must handle multiple requests (persistent connection).
- The servers must interpret boundaries differently.
- The smuggled data must form a valid, malicious request.

---

# Detection and Exploitation

## Detecting Vulnerabilities

1. **Timing Techniques**  
   - Send a request that causes the back-end to wait for additional data, leading to a noticeable delay.  
   - **CL.TE Example:**
     ```
     POST / HTTP/1.1
     Host: vulnerable-website.com
     Content-Length: 4
     Transfer-Encoding: chunked
     0
     X
     ```
     - The front-end sends 4 bytes, but the back-end expects more chunks, causing a timeout.

2. **Differential Responses**  
   - Send an attack request followed by a normal one; observe if the normal response is altered.  
   - **CL.TE Example:**
     ```
     POST /search HTTP/1.1
     Host: vulnerable-website.com
     Content-Length: 49
     Transfer-Encoding: chunked
     e
     q=smuggling&x=
     0
     GET /404 HTTP/1.1
     Foo: x
     ```
     - The back-end prepends `GET /404` to the next request, changing its response.

## Exploiting Vulnerabilities

- **Bypassing Security Controls**:  
  - Smuggle a request to access restricted resources.  
  - **Example:**
    ```
    POST /home HTTP/1.1
    Host: vulnerable-website.com
    Content-Length: 62
    Transfer-Encoding: chunked
    0
    GET /admin HTTP/1.1
    Host: vulnerable-website.com
    Foo: x
    ```
    - The front-end processes `/home`, but the back-end also executes `/admin`.

---

# Advanced Techniques

- **HTTP Request Tunneling**:  
  - Sends a single request that triggers two back-end responses, bypassing front-end checks even without connection reuse.  
- **HTTP/2 Downgrading**:  
  - When an HTTP/2 front-end converts requests to HTTP/1, attackers can inject `Content-Length` or `Transfer-Encoding` headers to desynchronize processing.
    
  <img width="1130" height="403" alt="image" src="https://github.com/user-attachments/assets/e83904ea-0532-4778-839e-4cd1b976ddf4" />


---
