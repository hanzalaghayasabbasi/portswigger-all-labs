# File Upload Vulnerabilities

## Lab Levels

Jump directly to the lab writeups:

* [APPRENTICE](./APPRENTICE_Lab.md)
* [PRACTITIONER](./PRACTITIONER_Lab.md)
* [EXPERT](./EXPERT_Lab.md)

  
## Introduction

File upload vulnerabilities are when a web server allows users to upload files to its filesystem without sufficiently validating things like their name, type, contents, or size. Failing to properly enforce restrictions on these could mean that even a basic image upload function can be used to upload arbitrary and potentially dangerous files instead. This could even include server-side script files that enable remote code execution.

In some cases, the act of uploading the file is in itself enough to cause damage. Other attacks may involve a follow-up HTTP request for the file, typically to trigger its execution by the server.

<img width="837" height="376" alt="image" src="https://github.com/user-attachments/assets/785a0588-2b72-4bc6-a879-ba1dcd5015ce" />




## Impacts of File Upload Vulnerabilities

File upload vulnerabilities can have severe consequences for a web application and its server:

1. **Web-shell Upload**: Attackers upload malicious scripts (e.g., `.php`, `.asp`) to execute arbitrary code, gaining unauthorized access.
2. **Reverse Shell Upload**: Malicious files establish a reverse connection to the attacker's machine, enabling persistent remote access.
3. **Remote Control**: Successful exploitation allows attackers to control the server and manipulate resources.
4. **Security Loss**: Compromises server integrity, confidentiality, and availability, exposing sensitive data.
5. **Financial Loss**: Breaches may lead to downtime, data theft, or ransomware, causing financial damage.
6. **File Overwrite**: Malicious files can overwrite critical system files, disrupting functionality.

## First Step: Information Gathering

To exploit file upload vulnerabilities, attackers gather key information:

1. **Server Version and Name**: Identify the web server (e.g., Apache, Nginx) and version to uncover vulnerabilities.
2. **Which Shell?**: Determine if a web-shell or reverse shell is feasible based on server configuration.
3. **Limitations**: Understand file size limits, upload quotas, or directory permissions.
4. **Web Shell or Reverse Shell**: Choose based on attack goals (direct execution vs. persistent access).
5. **Allowed Extensions**: Identify permitted file extensions (e.g., `.jpg`, `.png`, `.pdf`) and restrictions.

Additional reconnaissance may involve brute-forcing directories to locate upload paths.

## File Upload Vulnerabilities: Filtering Mechanisms

Web applications use client-side and server-side filtering to restrict uploads. Attackers analyze these for weaknesses.

### Client-Side Filtering

- **Description**: Filtering occurs in the browser (e.g., via JavaScript) before file upload.
- **Bypass Techniques**:
  1. **Method 1: Modify Source Code**
     - Inspect source code to locate JavaScript validation.
     - Disable/modify filtering code using browser developer tools.
     - Upload malicious file (e.g., `malicious.php`) and access it (e.g., `/uploads/malicious.php`).
  2. **Method 2: Intercept HTTP Request**
     - Use Burp Suite to intercept the upload request.
     - Remove/modify JavaScript validation (e.g., delete `.js` checks).
     - Forward the modified request, upload the file, and access it.

### Server-Side Filtering

- **Description**: Validation occurs on the server after upload, focusing on extensions, MIME types, content types, or size.
- **Types**:
  1. **Extension Filtering**:
     - **Blacklist Filtering**: Blocks extensions like `.php`, `.phtml`. Bypassed with alternate extensions (e.g., `.php5`, `.pht`) or double extensions (e.g., `file.jpg.php`).
     - **Whitelist Filtering**: Allows only specific extensions (e.g., `.png`, `.jpg`). Exploited via misconfigurations or malicious content in allowed files.
  2. **MIME-Type Filtering**:
     - Validates file MIME type (e.g., `image/jpeg`) based on magic bytes.
     - **Bypass Technique**:
       - Intercept request to identify allowed MIME types/extensions.
       - Collect magic bytes for allowed files (e.g., `FF D8 FF` for JPEG).
       - Prepend allowed magic bytes to a malicious file (e.g., PHP web-shell with `GIF89a`).
       - Upload and access the file.

        ➤ **Collect magic bytes for allowed files** from this reference:  
             [List of File Signatures (Magic Numbers)](https://en.wikipedia.org/wiki/List_of_file_signatures)
   
  3. **Content-Type Filtering**:
     - Checks `Content-Type` header (e.g., `image/jpeg`). Modify header to match allowed type.
  4. **File Length Filtering**:
     - Restricts file size. Bypassed with small malicious files or chunked uploads.

## Types of File Upload Vulnerabilities

1. **Extension-Based Vulnerabilities**:
   - Weak extension validation allows executable scripts (e.g., `.php`, `.asp`).
   - **Example**: Upload `shell.php` disguised as `shell.jpg.php`.

2. **MIME Type-Based Vulnerabilities**:
   - Weak MIME type validation allows malicious files with forged MIME types.
   - **Example**: Change MIME type of a PHP file to `image/jpeg`.

3. **File Size-Based Vulnerabilities**:
   - Unenforced size limits allow large files to overwhelm the server.
   - **Example**: Upload a massive file to cause a denial-of-service (DoS).

4. **Double Extension-Based Vulnerabilities**:
   - Weak validation allows double extensions (e.g., `file.png.php`).
   - **Example**: Apache may execute `file.jpg.php` as PHP if misconfigured.

5. **Tampering with HTTP Requests**:
   - Modify request parameters (e.g., `Content-Type`, `filename`) to bypass validation.
   - **Example**: Change `filename="shell.php"` to `filename="shell.jpg"`.

6. **Bypassing Client-Side and Server-Side Validation**:
   - Weak validation allows manipulation of file metadata to upload malicious files.

## Example: Bypassing MIME-Type Filtering


![image](https://github.com/user-attachments/assets/ade0ddf1-3986-4778-9e02-9f2e4951d745)


- **Analysis**:
  - File named `123.php` with `Content-Type: image/jpg` to bypass MIME validation.
  - Starts with `GIF89a` (GIF magic bytes) followed by PHP code (`<?php eval($_GET["cmd"]);?>`).
  - Allows a web-shell disguised as an image, executable if the server misinterprets it.

- **Steps**:
  1. Intercept upload request with Burp Suite.
  2. Modify `Content-Type` to an allowed type (e.g., `image/jpg`).
  3. Prepend valid magic bytes (e.g., `GIF89a`) to malicious PHP code.
  4. Upload and access via upload directory (e.g., `/uploads/123.php?cmd=whoami`).


## Tools for Testing File Upload Vulnerabilities

- **Burp Suite**: Intercept and modify HTTP requests.
- **Dirb/Gobuster**: Brute-force directories to locate upload paths.
- **Metasploit**: Craft and test web/reverse shells.
- **File Command (Linux)**: Analyze magic bytes for crafting files.

## Additional Notes

- **Directory Brute-Forcing**: Use tools like `dirb` or `gobuster` to find upload directories (e.g., `/uploads/`).
- **Double Extension Attacks**: Test by appending executable extensions (e.g., `file.jpg.php`).
- **Magic Bytes**:
  - JPEG: `FF D8 FF`
  - PNG: `89 50 4E 47`
  - GIF: `47 49 46 38 39 61` (GIF89a)
  - PDF: `25 50 44 46` (%PDF)


## Mitigation Strategies

To prevent file upload vulnerabilities:

1. **Strict Server-Side Validation**:
   - Use whitelists for extensions and MIME types.
   - Verify file content with magic bytes, not just headers.
   - Block executable extensions (e.g., `.php`, `.asp`).

2. **File Storage Best Practices**:
   - Store files outside the web root (e.g., `/var/uploads`).
   - Use randomized filenames.
   - Disable execution permissions in upload directories.

3. **MIME-Type and Content Validation**:
   - Use server-side libraries (e.g., `libmagic` in PHP).
   - Reprocess files (e.g., re-save images) to strip malicious code.

4. **File Size Limits**:
   - Enforce strict size limits to prevent DoS.
   - Validate size on both client and server sides.

5. **Secure HTTP Request Handling**:
   - Sanitize request parameters (e.g., `filename`, `Content-Type`).
   - Use secure file upload libraries.

6. **Content Security Policies (CSP)**:
   - Restrict execution of uploaded files.
   - Disable inline scripts and enforce MIME-type checks.

7. **Directory Brute-Force Protection**:
   - Restrict directory indexing and access.
   - Use `.htaccess` to deny direct access to uploaded files.
