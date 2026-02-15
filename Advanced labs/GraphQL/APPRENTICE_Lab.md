## Labs Covered

This write-up focuses on the following **APPRENTICE-level lab** from the PortSwigger Web Security Academy related to **GraphQL API Vulnerabilities**:

**1 Accessing private GraphQL posts**  
    This lab demonstrates how insufficient access controls on GraphQL queries allow unauthorized users to retrieve private data.

---

### LAB 1 - Accessing private GraphQL posts

### Lab Description

<img width="849" height="296" alt="image" src="https://github.com/user-attachments/assets/4333a178-957a-4bb7-857d-f43889f34273" />

### Solution

We recommend that you install the **InQL** extension before attempting this lab. InQL makes it easier to modify GraphQL queries in Repeater, and enables you to scan the API schema.”( I have install in burpsuite community in linux because this extension require latest version where our burp professionla have old version") 

<img width="969" height="733" alt="image" src="https://github.com/user-attachments/assets/68b472fa-7c41-463d-9bdb-215c4f7cf519" />


So if we look at summary tab of **/graphql/v1** which comes first when we start lab we can see that id:3 is missing


<img width="1623" height="598" alt="image" src="https://github.com/user-attachments/assets/e08840e9-eab2-4f99-96f3-0b7ec5569ae2" />


If we have no summary tab you shoud go to each and every blog and see what id is missing to get private blog which is not listed and the 
Request his attribute through graphql api


<img width="1417" height="584" alt="image" src="https://github.com/user-attachments/assets/e5dd8e2c-8bed-457c-b7f4-4e2b34342206" />




Now we have send  id:2 to repeater and we have notice that all the query which we have given in request graphql gives us reponse
According to that like in our case we  **request image,title,author,date,paragraph**.
Now we have to request samething for our private blog which is not showing all the remaning blog
Id  like **1,2,4,5** is showing but not 3 ,so it might be private we will request now 3 to get it's content


<img width="1674" height="572" alt="image" src="https://github.com/user-attachments/assets/4b714306-6fe4-4ce1-ab5b-db243ce3eeea" />


Now we have change **id:3** which gives us 3 content as shown in below image


<img width="1668" height="635" alt="image" src="https://github.com/user-attachments/assets/30bd3573-1725-4b2f-87f4-6ab06fa8c629" />


For your information, the advantage of GraphQL over other API’s like REST is that it we can retrieve only required, selective information from the database, unlike REST API which returns the entire object that is present.
So, we need to know the fields that the blogPost type contains of. For that, we need the InQL extension for Burp Suite.
So after installing InQL, move on to the InQL scanner tab and paste the GraphQL endpoint for your lab. After loading it, we can view the complete schema of the GraphQL API. From the results returned by InQL scanner, we can observer that the getBlogPost query also contains another field called the postPassword.

<img width="1900" height="269" alt="image" src="https://github.com/user-attachments/assets/0dd021b1-a448-4d02-b220-9ea04e7879a0" />




And Now we can see that graphql have gives us all the query of our endpoint which are in blog hidden.


<img width="1018" height="332" alt="image" src="https://github.com/user-attachments/assets/00970f68-fda0-4e8e-a435-854fd8cff2a1" />



And now we change **id:3** and the enter field of Postpassword and we have get Postpassword copy and paste post passowrd in lab submit and lab is solved

<img width="1665" height="539" alt="image" src="https://github.com/user-attachments/assets/872146aa-91e3-4f13-aead-b1497ca09452" />

 
Submit it and then lab is solved

<img width="1286" height="279" alt="image" src="https://github.com/user-attachments/assets/8ebdd627-710c-423d-b633-dd90e4d633d1" />


---


