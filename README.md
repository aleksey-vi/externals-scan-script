# Description
This utility is primarily designed for penetration testers and bug hunters. The script can work in two modes:
- 1 - You specify only the target domain.
- 2 - You specify a scope of domain addresses (or IP addresses).

The scanning process consists of several stages:
1. Subdomain reconnaissance (only if mode #1 is selected) and saving the list of live hosts to a file.
2. A separate directory is created for each domain (with the name of the scanned subdomain) in the `results` folder.
3. Scanning of open ports is performed, along with the identification of services running on them, their versions, and operating systems.
4. Scanning results are parsed and presented in the form of domainname:port. Based on this new list, the technologies used on the site are identified, and directories are crawled.
5. GET requests are sent to the list of found URL addresses with traffic proxied to BURP (default proxy address is 127.0.0.1:8080) to build a network map.

**ATTENTION!!!**
Make sure you have Burp running to proxy traffic; otherwise, you will receive `proxyconnect tcp: dial tcp 127.0.0.1:8080: connect: connection refused` errors.

6. Then, scanning for CVEs, misconfigurations, default credentials, etc., is performed on all open ports.

7. After scanning each host, the results are recorded in the infra.txt file in tabular format.

# Installation

## Dockerfile

Installation via this method is standard:

1. While in the directory with your Dockerfile, execute the command:

        sudo docker build -t your_name .

2. Create and run a new container from the image:

        sudo docker run name/id

3. Connect to the shell:

        sudo docker exec -it name/id /bin/bash

## Git Clone

This option is straightforward as well.

After cloning the repository, you need to install the required libraries from the `requirements.txt` file.

After that, simply run the script with the command:


# Usage

Before running the code, uncomment/comment the path to the Nuclei templates in the code, depending on whether you want to use templates from Cent or ProfectDiscovery!!!

    python3 ./scan.py

Using the script is extremely simple and intuitive.

1. Choose the mode.
2. Specify the domain or address scope (depending on the selected mode).
3. Enter cookies if necessary. If there are no cookies, simply press enter, and scanning will start.

## Utilities used

https://github.com/xm1k3/cent<br>
https://github.com/nmap/nmap<br>
https://github.com/projectdiscovery/nuclei<br>
https://github.com/projectdiscovery/notify<br>
https://github.com/projectdiscovery/dnsx<br>
https://github.com/projectdiscovery/httpx<br>
https://github.com/projectdiscovery/katana<br>
https://github.com/projectdiscovery/subfinder<br>
https://github.com/tomnomnom/fff<br>
https://github.com/tomnomnom/assetfinder<br>
https://github.com/tomnomnom/waybackurls<br>
