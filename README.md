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

        git clone https://github.com/aleksey-vi/externals-scan-script.git
   
3. change directory

        cd externals-scan-script

4. Build a new container from the image:

        sudo docker build . -t ess-image

5. Check help:

        sudo docker run --rm --name ess-container -v ./python3:/application -w /application ess-image ess.py --help


# Usage

Using the script is extremely simple and intuitive.

1.Specify a domain;<br>
2.Select a mode;<br>
3.If necessary, specify a list of subdomains;<br>
4.Enter cookies if necessary.<br>

        usage: ess.py [-h] -d DOMAIN -m MODE [-l DOMAIN_LIST] [-c COOKIE]

        options:
          -h, --help            show this help message and exit
          -d DOMAIN, --domain DOMAIN
                        Domain for scanning
          -m MODE, --mode MODE  Select mode: 1 - scan the entire domain completely, 2
                        - only a specific scope
          -l DOMAIN_LIST, --domain-list DOMAIN_LIST
                        Domain list for scanning(ONLY if use mode 2)
          -c COOKIE, --cookie COOKIE
                        Authentication cookie or token


# Example

An example of running a scan for the `api.hackerone .com` subdomain without using cookies

        sudo docker run --rm --name ess-container -v /home/kali/Desktop/docker_test/externals-scan-script/python3:/application -w /application scan-image ess.py -d hackerone.com -m 2 -l api.hackerone.com


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
