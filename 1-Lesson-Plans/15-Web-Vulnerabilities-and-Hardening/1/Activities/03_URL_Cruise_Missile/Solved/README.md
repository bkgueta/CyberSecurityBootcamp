## Solution Guide: URL Cruise Missile

#### Weaponized URL

1. How can a URL (also know as a URI) be used as a weapon against web servers?

    - The URL is made of different layers designed to access different parts of a website, such as webpages, emails, or bank account information, for example. 
    
        A URL can be manipulated by attackers to infiltrate these various parts of the web server architecture. 

2. A URL is composed of many parts. Define each part of a URL and match it with the corresponding segment in the example below:

   `http://example.com/add.asp?ItemID=123&Price=999`

    - Protocol: `http`. Identifies the protocol or application to use with the HTTP request.

    - Host Name: `example.com`. Targets a specific web server for the request of web resources.

    - Path: `add.asp?`. Identifies which of the host's web applications will be used to provide resources to the client.

    - Parameters: `ItemID=123&Price=999`. Specifically formatted data that interacts with back-end databases, email, and web servers, for example. 

    

#### Web Application Server

1. What are the three most popular web servers in use today?
   
   - Apache, Nginx, IIS

2. Name three ways a compromised web server can be used to perform an attack.

    - A defaced webpage can contain malicious content and links to inappropriate and offensive sites, which can damage a company’s reputation.

    - A compromised web server can be used to download malicious software (viruses, Trojans, botnets) to anyone visiting the webpage.

    - Compromised data can be used to commit fraudulent activities, leading to loss of business or lawsuits.

3. The typical web application server setup is composed of five basic components. Name and define each component.

    - The client: A user who interacts with a web server using HTTP or FTP through either a web browser or file transfer software.

    - A firewall:  A perimeter defense used to protect a web server placed behind it.

    - A web server: A program such as Apache, Nginx, or IIS that responds to a client's requests for web resources.

    - Web applications: The software that runs on a remote server, such as Facebook, Twitter, Amazon.

    - Databases: Typically the inner most part of the web architecture where data is stored, such as customer names, addresses, account numbers, and credit card info.


#### OWASP Top 10

1. What is the purpose of the OWASP Top 10?


    - OWASP TOP 10 was created to educate a wide audience of professionals about the consequences of web application security weaknesses. 
    
        The Top 10 offers resources and best practices to software engineers, managers, designers, and organizations about how to protect against threats.

2. How is OWASP Top 10 developed?


    - Over 500 individuals from various organizations who work on applications and API are surveyed. OWASP prioritizes the top ten threats based on prevalence data as well as exploitability, detectability and impact. 


3. What is OWASP's number one threat?

    - Code injection, such as SQL, LDAP, OS, and NOSQL.

4. What is the OWASP Cheat Sheet Series and what is it used for?

    - The OWASP Cheat Sheet Series (OCSS) is designed by application security professionals to provide a collection of significant information in regards to specific application security topics. 

--- 

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  