
## Activity File: Mapping the Database

In this activity, you will act as a security analyst at a major bank. You will learning the TTPs of attackers that intend to target your network. This activity is based on the "offense informs defense" philosophy. You will act as a criminal hacker in order to better understand how the exploits are carried out. 

- You will try to crack into the database of the banks in order to steal customer account information, which can then be sold on the dark web. 

- You will need to use SQLMap to exploit a potential vulnerability on the back-end database.


### Instructions

You will use the following VMs for this activity:

- Attacker: Kali Linux 
- Vulnerable Web Database: owaspbwa (OWASP Broken Web Apps) 

1. In owaspbwa:

   - Navigate to OWASP Bricks.
   - Select **Bricks** in the menu bar.
   - Click **Login Pages**.
   - Click **Login #1**.
   - Make sure you click the **x** in the **You are not logged in** box. 
   - Copy the URL of the Bricks Login page.

2. In Kali Linux, open a terminal and display the SQLMap help menu. Review the options, and clear the screen.
   
3. At the SQL prompt, enumerate database users. Use the URL from the owaspbwa Bricks Login screen. 

4. Enumerate the user passwords. 

   
5. Enumerate back-end databases. 
      
   
6. Enumerate all tables in the `bricks` database.
   
   
7. Enumerate the columns in the `users` table in the `bricks` database. 

   
8. Dump only the names, passwords, and emails from the selected columns.
   
   
9. Test out a few credentials on the Bricks Login page to see if the your exploit worked. 

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  