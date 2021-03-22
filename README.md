# It's so easy! (Ransomware PoC) 
![Ransomware: Attention](https://img.shields.io/badge/MALICIOUS!-Ransomware-informational)
> ATTENTION! This program code is malicious and can encrypt or/and delete personal data!

#### Disclaimer
> Attention! Use of the code samples and proof-of-concepts shown here is permitted solely at your own risk for academic and non-malicious purposes. It is the end user's responsibility to comply with all applicable local, state, and federal laws. The developer assumes no liability and is not responsible for any misuse or damage caused by this tool and the software in general.

### What?
This is a Ransomware Concept written in Python. Yes it is malicious. Yes, if you do that on VMs it is okay. Yes, if you misconfigured the architecture or network and encrypt your own files they are gone forever. 

### Why?
This PoC I've written for a educational project. Only for that! And because I am very interested in the topics of how malware is detected and works :D By the way, on Windows only 4 from 71 AV-Scanners detect the packaged and obfuscated client. On Linux only 1!

### How malicious is it?
Very! The program uses AES-256 encrption mode. The Keys where sent by the server using TLS. The Keys where directly deleted  after (en-) decryption. 


[![forthebadge made-with-python](http://ForTheBadge.com/images/badges/made-with-python.svg)](https://www.python.org/)
### Requirements:
* Python 3.7.9
* to install the requirements use pip with following command:
	-> python3 -m pip install -r requirements.txt
	-> installation of Tkinter with Linux or Windows commands

### Files:
* client.py -> the ransomware client
* setup.py -> the first executed program at packaged state -> starts the client
* server.py -> the server application
* requirements.txt -> all exclusive requirements for the program-code
* certs (directory) -> the TLS required certs for the server


### System-, Network architecture & Usage (only for educational testing!):
This is the test-environment I've used.
![Network Overview](img/network.png)
* Server: VBox Debian Linux Buster (Version 10) with 
	* host-only-adapter
	* static ip: paste it into client.py
	* for example Apache2 with website for delivery
	* MariaDB (MySQL) 
		* with user root and password toor (or change it :D)
		* database itsSoEasy and table clients
			* columns:
				* id : int, primary key, auto-increment, no-null
				* userIdentity : varchar(255), no-null
				* userKey : varchar(100), no-null
				* userIV : varchar(100), no-null
				* additional : varchar(255)
	* itsSoEasy-Server -> server.py:
		* port 6666
		* creates logging file
		* needs "certs" folder in the same directory to start TLS-connection

* Client:
	* NAT (internet and internal ips)
		-> needs no static ip!
	* Ubuntu 20.04 (Focal Fossa), Windows 10
	* for example usage of precompiled binarys:
		* per delivery on website from server
	* >ATTENTION: will encrypt whole Documents directory on both os!
	* automatically requests a decryption after several seconds
	* >ATTENTION: debugging will be detected! 
		* At the begin, process list will be analyzed
		* during execution time will be taken, if more than 1,5 seconds 
			programm opens google.de and kill itself.
			> -> ATTENTION for vboxes with minimal ram or hdd-disks usage
		* if event killed itself, start again, process will do his thing (encryption or decryption)
	* if not payed the ransom, after restart, it starts automatically
	* killing process with STRG-C will not work!
	* removes itself and all his created files automatically when procedure is done

	* Install without binarys (if ip-addresses or ports has changed):
		* use described python version and requirements
		* create a (obfuscated) binary of client.py with pyinstaller or pyarmor (see elaboration)
		* pack setup.py with compiled client.py with pymakeself
		* create binary from packed python file with pyinstaller


### Full Procedure
![procedure](img/procedure.png)


### Some screenshots while ItsSoEasy is in action :D

* A friendly welcome message
![linux_whoops](img/linux_whooops.png)
![windows_whoops](img/windows_whoops.png)

* How to pay (opened in default browser)
![ransom_message](img/ransom_message.png)

* The Clou: Is it easy enough for you? ;)
![the_clou](img/itssoeasy.png)