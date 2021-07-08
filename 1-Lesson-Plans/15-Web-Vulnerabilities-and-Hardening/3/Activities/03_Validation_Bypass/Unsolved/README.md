## Activity File: Client-Side JavaScript Validation Bypass

This activity is based on the "offense informs defense" philosophy. You will practice taking the role of a criminal hacker in order to better understand how exploits are carried out. Remember: to protect from attacks, you'll need to practice thinking like an attacker. 

- In this activity, you will play the role of criminal hacker attempting to steal usernames and passwords. 

- You will bypass input validation and perform a SQL injection to exploit a vulnerability that you've discovered in a company's web server.

- **Note:** If you had turned off Javascript in the previous example and have not turned it back on, please do so now. Follow the steps below:


### Instructions

1. In owaspbwa, identify the IP address of the vulnerable web application.

   - Launch terminal and run `ifconfig`. 

   In your Kali VM, launch firefox, enter the IP address in the browser and navigate to the following webpages:  
   - Mutillidae II > Others > JavaScript Validation Bypass > User Info SQL


    Set security level to **1 - Client Side Security**, a slightly elevated level of security that activates the JavaScript validation process. To do this, click **Toggle Security** button in the navigation bar.

2. Perform a SQLi attack on both the username and password fields.

   - Type the command that performs a SQLi into empty fields, then click **View Account Details**.

      - This command will inject code into the back-end database.

      -  An error box should pop up. Click **OK**.

3. Disable JavaScript from performing the client-side validation.

   - Open a new tab and type the command that opens the Firefox configuration window into the URL. Press Enter. 

   - Type the parameter used to edit JavaScript in the search box.

   - Change the setting necessary to disable Javascript.

4. Click **OK** and reload the page. Type the the SQLi commands into each form field again and click **View Account Details**.

   - What is the output?
   
When you are finished, re-enable JavaScript. 

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
