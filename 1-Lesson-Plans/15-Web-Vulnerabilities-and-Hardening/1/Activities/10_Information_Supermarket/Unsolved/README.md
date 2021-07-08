## Activity File: Information Supermarket

In this activity, you will continue your role of a security analyst working at DigiLink Inc.

- Your CISO released an internal security bulletin that reveals an increase in social engineering attacks using information from freely available resources on the internet.

- Knowing that it's impossible to avoid having some information publicly available, your CISO asked you to research ways to reduce the company's attack surface.


### Instructions


#### Reconnaissance

First, you'll identify sources that an attacker could use to gather information against your company and its employees. 

1. Name seven pieces of information that an attacker could easily find on the internet that would be useful to them.  

As part of your investigation, you will use two command-line tools to help identify what information is publicly available on the internet.

2. Perform a `whois` against SacBee.com and identify information that would be useful in a social engineering attack.


3. Perform a `whois` against HackingTeam.com. How is the output different this time?

4. What are some popular websites that an attacker could visit to find information useful for crafting social engineering campaigns against individual employees? What kind of information can be found on these sites? 


#### Web Application Firewalls

Now you'll use Wafw00f as an information gathering tool to determine if a website is protected by a web application firewall, and then perform a more detailed analysis.

1. Perform a WAF test using Wafw00f against http://www.example.com. Is this site behind a WAF and if so, which one?


2. What layer of the OSI model do WAFs operate on?


3. Name three ways a WAF can be implemented.


4. A WAF helps protect web applications by filtering and monitoring what?


5. True or False: A WAF based on the **negative security model** (blacklisting) protects against known attacks, and a WAF based on the **positive security model** (whitelisting) allows preapproved traffic.


---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  