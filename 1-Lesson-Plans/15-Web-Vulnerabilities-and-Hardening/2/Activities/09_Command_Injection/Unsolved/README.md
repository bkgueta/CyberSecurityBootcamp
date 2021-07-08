## Activity File: Command Injection

In this activity, you will act as a security analyst learning the TTPs of attackers that intend to target your company. This activity is based on the "offense informs defense" philosophy. You will act as a criminal hacker in order to better understand how the exploits are carried out. 

- In the following activities, you will act as a criminal hacker exploiting a vulnerability in the company’s web server that may allow you to steal the `/etc/passwd` file.

- Your objective is to perform a command injection attack that will dump `/etc/passwd` file into a text document, archive it, and compress it in preparation for exfiltration.

- The quieter you are, the less likely it is that you'll get caught. 

### Instructions

Launch the following machine environments: 

- Attacker: Kali Linux
   - Username: `root`
   - Password: `toor`

- Vulnerable Web Server: owaspbwa
   - Mutillidae II

1. In the owaspbwa machine, identify the local IP.

   - Document the IP. You will use it in the following step.

2. In Kali, open Firefox and type the IP of the owaspbwa VM into the URL.

   Navigate through the following webpages:

   - OWASP 2013 > A1 Injection (Other) > Command Injection > DNS Lookup

   - Set security level to **Hosed**.

   You will see a window that says **DNS Lookup**.

3. In the DNS Lookup window, enter the command into the **Hostname/IP** box to reveal the contents of the `/etc/passwd` file. 

4. Perform a command injection that creates a file called `hack.txt` and forwards the contents of the `/etc/passwd` file to it. Then archive it and compress it.
   
#### Bonus 

Navigate to owaspbwa (the vulnerable web server) > Mutillidae II > OWASP 2013 > A1 Injection (Other) > Command Injection > DNS Lookup

- Use the following steps to perform a command injection that allows you to exfiltrate a list of users from the vulnerable web server  to the attacker's machine in a test file named `hacked.txt`:

   - Type the command injection into the webpage that establishes a listener on the vulnerable web server.
   
   - In the terminal, type the command that connects to the listener on the web server.
   
   - Type the command that copies the `/etc/passwd` into a text document called `hacked.txt`.
   
   - Type the command that reads the contents of `hacked.txt`.
   
   What results are returned?
   
---
© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
