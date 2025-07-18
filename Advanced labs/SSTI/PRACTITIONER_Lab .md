## Labs Covered

This write-up focuses on the following **PRACTITIONER-level labs** from the PortSwigger Web Security Academy related to **Server-side template injection (SSTI)**:

**Basic server-side template injection**  
This lab demonstrates how attackers can inject server-side template expressions to execute arbitrary code or access sensitive data.

**Basic server-side template injection (code context)**  
This lab shows SSTI exploitation when template expressions are directly evaluated in code execution context.

**Server-side template injection using documentation**  
This lab demonstrates how official template engine documentation can help attackers craft effective SSTI payloads.

**Server-side template injection in an unknown language with a documented exploit**  
This lab explores how attackers can exploit SSTI in template engines even when the backend language is unknown, by leveraging known techniques.

**Server-side template injection with information disclosure via user-supplied objects**  
This lab demonstrates how attackers can supply specially crafted objects to disclose information during SSTI exploitation.

---

### LAB 1 - Basic server-side template injection

### Lab Description

<img width="787" height="254" alt="image" src="https://github.com/user-attachments/assets/9c21e9fa-42eb-43e6-9d1c-ff29e2b5a289" />

### Solution

When I clicked  blow image the message comon above I **Unfortunately product is out of stock** appear

<img width="580" height="580" alt="image" src="https://github.com/user-attachments/assets/6962e768-0b00-4489-974b-69d92b9515ae" />

Now I try all payload  but I find below paylaod is evaluted ,So now I goto hacktrick to knew what tempalte it is.

<img width="995" height="398" alt="image" src="https://github.com/user-attachments/assets/75d9546a-7b10-41de-812e-9b1cc4241ea2" />

Now search in hactrick but we have two more,So look closely  while selecting syntax proper testing should be performed

<img width="663" height="381" alt="image" src="https://github.com/user-attachments/assets/14d18038-d376-42ac-b615-d05228b1e8b9" />

Now to confirm this we add **whoami** wrong and error tell use this is ruby

<img width="1125" height="514" alt="image" src="https://github.com/user-attachments/assets/8d940544-75cb-44e7-8be0-e947506d94d2" />

So now we do whoami and give us carlos so now we have to remove **morale.txt** to solved the lab

<img width="1043" height="277" alt="image" src="https://github.com/user-attachments/assets/15e8bffb-a7eb-48e6-8667-d924fa24c550" />

	Remove `morale.txt`  and lab is solved

<img width="1095" height="291" alt="image" src="https://github.com/user-attachments/assets/8df9ff1a-405f-41e6-a0c2-2a54e21efa60" />

<img width="1084" height="395" alt="image" src="https://github.com/user-attachments/assets/150cb00b-8d46-4270-9027-d69d03df93f2" />

---

### LAB 2 - Basic server-side template injection (code context)

### Lab Description

<img width="748" height="400" alt="image" src="https://github.com/user-attachments/assets/dbd7d6ed-6462-4792-9b3d-46693a892ff0" />

### Solution

While commenting none of payload is not working

<img width="640" height="344" alt="image" src="https://github.com/user-attachments/assets/5ba64819-38e4-4fd9-9c1b-ba674df116e1" />

I enter submit and the look at burp intercept 

<img width="857" height="556" alt="image" src="https://github.com/user-attachments/assets/75cace03-ced9-4dfc-8f6b-92f3f07effbf" />

As we see user.template look like template

<img width="1064" height="600" alt="image" src="https://github.com/user-attachments/assets/b9347b8f-b54d-40b5-98bb-b3486ff05bc8" />

So now have comment above we will manipulate user.name with wrong things so where our user is coming where we comment it so there our name is will genrate error and we will get the  template of our website which is **tarnado** python


<img width="1046" height="154" alt="image" src="https://github.com/user-attachments/assets/7d1e71ea-0d2e-41e8-bd05-0e81ed1319a0" />


<img width="1026" height="732" alt="image" src="https://github.com/user-attachments/assets/283dc4cc-286d-4cef-a94a-6a01f356c3d8" />

Now we will run so it will get the whami result

<img width="1313" height="513" alt="image" src="https://github.com/user-attachments/assets/8df7a940-4978-4e49-982f-23aa4722bb28" />

How we carfted payload

<img width="1176" height="256" alt="image" src="https://github.com/user-attachments/assets/d93f09a4-ebba-4bea-a2b0-93b620619779" />

So when we run os command  below result we can see whoami result **carlos**

<img width="615" height="189" alt="image" src="https://github.com/user-attachments/assets/dcb4e4d6-e462-45ab-88b5-a4cdf69b71df" />

Now remove **moral.txt** and get flag

<img width="1463" height="482" alt="image" src="https://github.com/user-attachments/assets/633efd6b-53fb-4904-9d4c-8878d5d38eaf" />

<img width="945" height="243" alt="image" src="https://github.com/user-attachments/assets/1b38c5de-8ded-4e1b-a3d4-f07586b75a0a" />


---

### LAB 3 - Server-side template injection using documentation

### Lab Description

<img width="746" height="512" alt="image" src="https://github.com/user-attachments/assets/84104789-340c-4745-acf0-45e477b336ee" />

### Solution

So when we edit template and give wrong object instance of name give it king then it will gives us error and  and template name

<img width="770" height="74" alt="image" src="https://github.com/user-attachments/assets/c0cd4aa9-0f98-42b0-9bb9-9f5f4804cb07" />

Now the error will tell us the template being used which is **freemarker java** now we will search on hacktricks

<img width="1447" height="198" alt="image" src="https://github.com/user-attachments/assets/c4a57145-8e25-4445-ac64-547b6eff47ff" />

So we will used below template

<img width="532" height="271" alt="image" src="https://github.com/user-attachments/assets/f72ce9c0-f006-4562-b2cf-e192c9268b41" />


As we can see result **49** is coming when we save it

<img width="822" height="360" alt="image" src="https://github.com/user-attachments/assets/1072cb1b-9ecd-49fe-ba02-ed873989a013" />


So we used free mark payload of ssti and get carlos as  shown below now we will remove morla.txt and lab will be solved


<img width="682" height="386" alt="image" src="https://github.com/user-attachments/assets/f3173303-60f2-4110-90d6-8089f067f909" />


---

### LAB 4 - Server-side template injection in an unknown language with a documented exploit

### Lab Description

<img width="751" height="281" alt="image" src="https://github.com/user-attachments/assets/c34a172d-e563-4c5a-9488-a7fa0d1c306c" />

### Solution

When click on first product we see the **unfortunaltly product is out of stock** so our click is reflected we can try ssti

<img width="421" height="480" alt="image" src="https://github.com/user-attachments/assets/4116f4a1-dc77-4d87-be18-93a657a0e389" />

We have this but when I change input it is not reflected so we will not get ssti so we will look at where our input is reflected.


<img width="1211" height="353" alt="image" src="https://github.com/user-attachments/assets/d975858f-b1b1-415f-89b2-7b0038326f51" />

So instance of clicked at product reload page and intercept it through burp and say that our input is reflected so we can try our ssti here

<img width="1165" height="376" alt="image" src="https://github.com/user-attachments/assets/086af9f5-6b72-455a-b9e0-cfd791dcd723" />

Now when we try our first payload it gives us error  which will reveal it template which is handler bar oin node js  then used hacktricks to find template and get it 

<img width="1704" height="505" alt="image" src="https://github.com/user-attachments/assets/ff33266f-6869-47ab-b156-24843abe93f5" />


<img width="328" height="309" alt="image" src="https://github.com/user-attachments/assets/77bfe743-0033-4c0f-a0a3-aba1f3e5868e" />

We get same result

<img width="1100" height="387" alt="image" src="https://github.com/user-attachments/assets/d8fbc7b4-c934-4e48-ae97-15b2fddbdfc9" />


In exec whaomi command below result will come

<img width="1161" height="605" alt="image" src="https://github.com/user-attachments/assets/8e70604c-4b45-4223-ad5c-508c61dd521c" />

So when I enter `rm  /home/` it will delete `moral.txt`

<img width="862" height="258" alt="image" src="https://github.com/user-attachments/assets/9cc6cd22-6cba-43af-92d1-2c698fd4c350" />

The reason it thing error is coming because obsfucation is used for external connection so we can also curl the domain and gets its ip.

<img width="1053" height="229" alt="image" src="https://github.com/user-attachments/assets/b0f5bccc-28fb-4e4d-ba84-016583ef1fc5" />

Copy above paylaod in message box and get the result and submit it and lab will be solved

<img width="510" height="155" alt="image" src="https://github.com/user-attachments/assets/f92dbd1c-36b3-48e7-8ef1-16da25df3343" />


---

### LAB 5 - Server-side template injection with information disclosure via user-supplied objects

### Lab Description

<img width="772" height="389" alt="image" src="https://github.com/user-attachments/assets/a7ce9f87-76e2-46a5-b92d-c8a9132326cc" />

### Solution


When I am giving invalid template it is giving me nothing as shown below.

<img width="924" height="276" alt="image" src="https://github.com/user-attachments/assets/ec8229a6-7051-4168-bdfd-ecbc6a50df10" />

But when I am giving nothing in template it is givng me error and with tempalte being used:

<img width="948" height="127" alt="image" src="https://github.com/user-attachments/assets/6d2098f6-722e-4a57-88c1-0f614b1dde8b" />


Below is error message which is telling django template in python.

<img width="1478" height="199" alt="image" src="https://github.com/user-attachments/assets/548c8669-9bf3-4f84-949e-a6122226c221" />

Now when we search on hacktrick but did not find anyting so we search on google so we used <% debug %> to get debugging info.


<img width="1565" height="963" alt="image" src="https://github.com/user-attachments/assets/f67fe9ca-3bd3-481b-b778-b17891477a1d" />

We will get debug info


<img width="1448" height="708" alt="image" src="https://github.com/user-attachments/assets/2130e4e0-ddc1-40d5-8874-709eda2bba23" />


Some code of config file as shown below 

<img width="661" height="673" alt="image" src="https://github.com/user-attachments/assets/9f02b4f5-87fd-4255-9942-4382af6ceab6" />

Now I paste this in chatgpt and bard and ask how do I get secret key and got that

So we have setting parmater set so we used it get the secret key


<img width="1115" height="275" alt="image" src="https://github.com/user-attachments/assets/0cf3be86-33fc-4b09-901d-830e1dc72065" />

An get the secret key as shown in corner highlight in blue we used settings.secret  key template we get  secret key  `B470kmufjldtcwixfwlhiyhfalliat62` and  then lab is solved

<img width="947" height="375" alt="image" src="https://github.com/user-attachments/assets/8db52f4b-f3d8-4555-a981-8c7fac8f1174" />





---




---
