## Solution Guide: Information Supermarket

This activity was designed to strengthen your understanding of the threats posed by social networks and other sources of freely available online information to an organization's infrastructure and sensitive data.

---

#### Reconnaissance

First, you'll identify sources that an attacker could use to gather information against your company and its employees. 

1. Name seven pieces of information that an attacker could easily find on the internet that would be useful to them.  

    - IP address scheme, domain information, port state (open/closed/filtered),  email addresses, operating system banner,  employee names,  phone numbers.

As part of your investigation, you will use two command-line tools to help identify what information is publicly available on the internet.

2. Perform a `whois` against SacBee.com and identify information that would be useful in a social engineering attack.

    - Registrant, admin, and technology info that includes names, street and email addresses, phone number, and domain info.


3. Perform a `whois` against HackingTeam.com. How is the output different this time?

    - All company information has been redacted for privacy.

4. What are some popular websites that an attacker could visit to find information useful for crafting social engineering campaigns against individual employees? What kind of information can be found on these sites? 

    - LinkedIn: Type of hardware and software a company uses, first and last names of employees, employee position information, length of employment, prior work history, education, skills and endorsements, and previous projects.

    - Facebook: Names of friends and family, favorite hobbies, vacation spots, favorite books and movies, favorite foods, and restaurants.

    - Twitter: Personal, political, and religious views.

#### Web Application Firewalls

Now you'll use Wafw00f as an information gathering tool to determine if a website is protected by a web application firewall, and then perform a more detailed analysis.

1. Perform a WAF test using Wafw00f against http://www.example.com. Is this site behind a WAF and if so, which one?

    - Yes, an Edgecast (Verizon Digital Media) WAF

2. What layer of the OSI model do WAFs operate on?

    - Layer 7: Application

3. Name three ways a WAF can be implemented.

    - Network-based, host-based, and cloud-based

4. A WAF helps protect web applications by filtering and monitoring what?

    - HTTP traffic between web applications and the internet

5. True or False: A WAF based on the **negative security model** (blacklisting) protects against known attacks, and a WAF based on the **positive security model** (whitelisting) allows preapproved traffic.

    - True

---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  