## Solution Guide:  Client vs. Server-Side Attacks

### Client-side attacks

1. Cross-site scripting (XSS)

    - Allows attackers to inject malicious code into a website in order to intercept user sessions, vandalize websites, steal data, and control a user's browser.


2. Clickjacking

    - Tricks users into clicking misleading graphics that will then trigger an exploit. For example: A button that reads "Download" in large text.

3. Content spoofing

    - Tricks a user into believing that certain website is legitimate. For example, a fake login page that steals your credentials after you submit them. 


4. Drive-by download

    - Triggers downloads upon visiting a webpage without the users knowledge.


5. Phishing (social engineering)

    - A form of social engineering that manipulates a user into providing personal confidential information, such as user credentials and bank account information.

### Server-Side Attacks

Define each of the following server-side attacks:


1. Website defacement
    - An attack against a website that alters the appearance and information contained on a website or webpage. 


2. HTTP response splitting (CRLF injection)
    -  A type of web server vulnerability where the server does not properly sanitize input values, such as character returns (CRs) and line feeds (LFs).

3. Web cache poisoning

    - An attack that replaces legitimate cached web pages with malicious content.

4. Parameter or URL tampering

    - An attack that manipulates parameters passed to a web server in a URL.


5. Path or directory traversal (dot-dot-slash attack)

    - An attack that navigates into senstive files and directories by using dot-dot-slash (`../`) (as if navigating through directories in a terminal) in the URL. 


### Name that Attack

1. An organization's homepage is altered with an image of a skull and crossbones and a message that says "Animal Murderers!" Organizations that experience these types of attacks are usually seen as incompetent in the public eye, resulting in reputation damage.
   
   - Website defacement, often used by politically-motivated hacktivists. 

   
2. An attacker controls another HTTP response after the first response, in order to mount attacks.

    - HTTP response splitting (CRLF)
   
3. A legitimately cached web page sends a user to a malicious website.
 
    - Web cache poisoning
 
4. A URL was changed:
 
     Before: http://example.com/add.asp?ItemID=123&Price=999  
     After: http://example.com/add.asp?ItemID=123&Price=001

    - Parameter tampering


5. A URL was changed to http://some_site.com.br/../../../../etc/shadow.

    - Path or directory traversal

**Bonus**

1. You find a URL that contains the following code: `%co%af %e0%80%a`. 
    
    -  Unicode

---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
