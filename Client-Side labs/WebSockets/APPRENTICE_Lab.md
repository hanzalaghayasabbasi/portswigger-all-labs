## Labs Covered

This write-up focuses on **APPRENTICE** labs from the PortSwigger Web Security Academy related to **WebSockets**:

**Manipulating WebSocket messages to exploit vulnerabilities** *(APPRENTICE)*  
This lab demonstrates how attackers can manipulate WebSocket messages directly to exploit application vulnerabilities.

---

### LAB 1 - Manipulating WebSocket messages to exploit vulnerabilities

### Lab Description

<img width="879" height="338" alt="image" src="https://github.com/user-attachments/assets/640732a7-e891-4ab0-a1c3-d91d8533a260" />

### Solution

The lab application is a shop website offering chat support. After loading the page, I go straight to the chat feature. So I start annoying the agent:

I clicked hello and king and it is given at chat feature

<img width="1847" height="690" alt="image" src="https://github.com/user-attachments/assets/80395acb-1f5d-437b-8887-b1bcb8953c0f" />

The message exchange runs via WebSockets, with me sending messages to the server and the server sending back whatever needs to be written in the chat on my side (including a mirror of my own messages):

<img width="1392" height="531" alt="image" src="https://github.com/user-attachments/assets/da1e99c3-65b1-4498-aeba-0ae8f625bc28" />

First I send client message to repeater   

<img width="978" height="381" alt="image" src="https://github.com/user-attachments/assets/7489e76a-25cd-4621-bbca-ef63baa4b1fb" />

So I put the message into Repeater and start playing around and enter **h2** in tag.

<img width="1895" height="428" alt="image" src="https://github.com/user-attachments/assets/35658044-027b-4876-b195-b528431b5360" />


As we can see below the result is now in h2 tag is refelected in website but when I REFRESH IT WILL Gone because we have make changes on client side 

<img width="1024" height="548" alt="image" src="https://github.com/user-attachments/assets/d149cc0b-debd-44e5-9742-ca9fa497301a" />



 I try running a script via an `<img> `tag

<img width="1868" height="439" alt="image" src="https://github.com/user-attachments/assets/f7ec027b-083f-41a4-870b-2f8287cbc0bb" />

As we can see that we have making change in client side an the website it is giving us alert but after refresh it will be  gone

<img width="1907" height="664" alt="image" src="https://github.com/user-attachments/assets/a76ed56d-009d-4c13-807e-7230787c2a2e" />


So Now we have send server side request on repeater  to make change permenatly


<img width="1312" height="586" alt="image" src="https://github.com/user-attachments/assets/3554b973-7618-4ad9-a8f3-579b59a4a2f1" />


Genrating alert in img because whetver we type is written in html tags.

<img width="1920" height="473" alt="image" src="https://github.com/user-attachments/assets/4ec04510-43fc-48fa-b681-c28e292ccc61" />

Of course, as the content gets reflected, I also get that popup, confirming that it worked at least on my side:After reflected lab will be solved


SO we have make changes on sever side ,after refresh alert message is coming and lab is solved.

<img width="1735" height="657" alt="image" src="https://github.com/user-attachments/assets/3f2e9564-643e-4f70-af1e-03d7f36e0815" />


---



