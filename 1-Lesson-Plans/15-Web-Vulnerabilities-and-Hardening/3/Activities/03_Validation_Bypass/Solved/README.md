## Solution Guide: Client-Side JavaScript Validation Bypass

In this activity, you performed a client-side JavaScript validation bypass. This kind of practice will help you better understand the attack process so you can be better prepared to defend against it. 

---

1. In Firefox, navigate to the User Info SQL webpage on the OWASP Broken Web App page. 

   - Set security level to **1 - Client Side Security**, a slightly elevated level of security that activates the JavaScript validation process. To do this, click the **Toggle Security** button in the navigation bar.

2. Perform a SQLi attack on both the username and password fields.

   - Type `' OR 1=1 --'` in the username and password fields. 

3. Open a new tab and type `about:config` into the URL to open the Firefox configuration window. 

   - Type "JavaScript" in the search box. 

   - Double-click on the JavaScript line to change the value to **false**, indicating that JavaScript has been disabled.

4. Type the the SQLi commands into each form field again, then click **View Account Details**: 

   - `' OR 1=1 --'`
   - `' OR 1=1 --'`

   We should see the username, password, and signature fields returned from the back-end database.

Return to the `about:config` page and enable JavaScript.

---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  