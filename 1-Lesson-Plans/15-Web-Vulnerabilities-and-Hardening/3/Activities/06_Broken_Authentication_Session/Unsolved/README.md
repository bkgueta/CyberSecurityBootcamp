## Activity File: Broken Session and Authentication Management

In this activity you will play the role of a junior security administrator at LightSpeed Inc., an internet service provider.

- You've alerted management about security flaws in the company’s authentication system.

- You must demonstrate that these flaws exist and then provide recommendations for prevention and mitigation.

### Setup

Use the following VM environment setup:

- Attacker: Kali Linux 
- Vulnerable Web App: bWAPP

In Kali, launch Firefox and navigate to the owaspbwa website.

- Create a user account with the following credentials:
  - Username: `hacker`
  - Password: `exploit`

### Instructions

#### Part 1: Insecure Login Forms

1. In Kali, launch Firefox and navigate to the IP address of the OWASP BWA machine. Complete the following:
   - On the landing page, select the **bWAPP** module. 
   - Log in with the credentials `bee:bug`. 
   - On the drop down menu in the top right, sroll down and select **Broken Authentication - Insecure Login Forms**. 
   - Click on **Hack**.
   - Make sure the security level is set to Low.

- Login with the following credentials:
  - Username: `hacker`
  - Password: `exploit`

2. Submit the login. This should deliver an “Invalid Credentials” error message. After receiving this message, how do you acquire the username and password?

3. Attempt to log in using these stolen user credentials. What was your result?
   
4. Why does this web vulnerability exist?

5. How would you would mitigate this web vulnerability?

#### Part 2: Logout Management

1. Select **Broken Auth – Logout Management** from the **Choose your Bug** dropdown menu.
   
   - Click **Hack**.

   You should still be logged in from the last activity as user `hacker`. 

   - Click **Logout**.

2. Execute the logout management exploit.

3. Why does this web vulnerability exist?

4. How would you would mitigate this web vulnerability?

#### Part 3: Administrative Portals

1. Select **Session Management – Administrative Portals** from the **Choose your Bug** dropdown menu.

   - Click **Hack**.
   
   This page is locked. How can you gain access to it?
   
2. Why does this web vulnerability exist?

3. How would you would mitigate this web vulnerability?

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
