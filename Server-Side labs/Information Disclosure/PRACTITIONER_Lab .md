## Labs Covered

This write-up focuses on the following **PRACTITIONER-level lab** from the PortSwigger Web Security Academy:

- **Information disclosure in version control history**  
  This lab demonstrates how sensitive information, such as credentials or configuration data, may be exposed in version control history and can be extracted by attackers to compromise the application.

---

## LAB 5 - Information disclosure in version control history

### Lab Description :

![image](https://github.com/user-attachments/assets/3338b09e-df73-4c54-8abf-e867af5d5d10)


### Solution :
`
## Overview
- Virtually all websites are developed using some form of version control system, such as Git. By default, a Git project stores all of its version control data in a folder called `.git`.
- Occasionally, websites *expose this directory in the production environment*. In this case, you might be able to access it by simply browsing to `/.git`.


![image](https://github.com/user-attachments/assets/c87c034f-7c45-4177-bddd-022abfbe266f)


![image](https://github.com/user-attachments/assets/98259e75-dc37-492e-9a18-3360392023e4)

## Solution

### Step 1: Verify .git Directory Exposure
- Load the website and navigate to the `.git` directory: `https://<LAB-ID>.web-security-academy.net/.git` (replace `<LAB-ID>` with your lab's unique identifier).
- The page should display disclosed Git files, similar to this:

![image](https://github.com/user-attachments/assets/26a95f85-5377-45ad-872c-19d41afea143)


### Step 2: Retrieve the Admin's Password

#### Tool: Git-Dumper
- Use the `git-dumper` tool (available at [https://github.com/arthaud/git-dumper](https://github.com/arthaud/git-dumper)) to analyze the exposed `.git` files.
- Install `git-dumper` if needed (e.g., `git clone https://github.com/arthaud/git-dumper.git` and follow setup instructions).

#### Step 2.1: Download the .git Repository
- Run the following command to save the `.git` directory and files to a local folder (e.g., `websecurity`):
  ```bash
  python3 git_dumper.py https://<LAB-ID>.web-security-academy.net/.git websecurity/
  ```
  - Replace `<LAB-ID>` with your lab's identifier.

#### Step 2.2: View Commit History
- Navigate to the `websecurity` directory:
  ```bash
  cd websecurity
  ```
- Check the commit logs with:
  ```bash
  git log
  ```
- This reveals two commits:
  ```git
  commit 63085ffc69c9cab7029684ec63ba9219cb96f851 (HEAD -> master)
  Author: Carlos Montoya <carlos@evil-user.net>
  Date:   Tue Jun 25 14:05:07 2020 +0000

      Remove admin password from config

  commit 19dd0c8f15df85cd3526e0d51e9f912d3e52c556
  Author: Carlos Montoya <carlos@evil-user.net>
  Date:   Mon Jun 25 16:23:42 2020 +0000

      Add skeleton admin panel
  ```

#### Step 2.3: Extract the Removed Password
- Compare the commits to find the deleted password:
  ```bash
  git diff 19dd0c8f15df85cd3526e0d51e9f912d3e52c556 63085ffc69c9cab7029684ec63ba9219cb96f851
  ```
- The output shows the change in `admin.conf`:
  ```git
  diff --git a/admin.conf b/admin.conf
  index ec58905..21d23f1 100644
  --- a/admin.conf
  +++ b/admin.conf
  @@ -1 +1 @@
  -ADMIN_PASSWORD=sdesf4efrgftrefrgregf
  +ADMIN_PASSWORD=env('ADMIN_PASSWORD')
  ```
- The removed password is **administrator:sdesf4efrgftrefrgregf`**.

### Step 3: Login and Delete User Carlos

#### Step 3.1: Log In as Admin
- Access the admin panel (e.g., `https://<LAB-ID>.web-security-academy.net/admin`).
- Log in with the credentials:
  - Username: `administrator`
  - Password: `sdesf4efrgftrefrgregf`

![image](https://github.com/user-attachments/assets/0d8b1267-7305-4301-9ffd-c1aaf43c462b)


#### Step 3.2: Delete User Carlos
- Navigate to the user management section in the admin panel.
- Find and delete the user "carlos" to complete the lab.

![image](https://github.com/user-attachments/assets/a0ec5216-301a-4c4f-aae3-9c52d6ebaf0e)


---

