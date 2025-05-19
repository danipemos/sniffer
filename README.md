# Titulo

## Description
Sniffer designed in Python using the libraries Scapy and Pcapy, focusing on data protection, security, and privacy. This tool is intended to be executed as a service. The sniffer's configuration is located in the /etc/sniffer/config.ini folder. The options for the tool are explained in (help.txt). Capture files will be stored in /etc/sniffer/captures. To manipulate the capture files and the config.ini as a local user of the machine, add this user to the sniffer group.
## Key Features
  - Select the interface to sniff
  - Set a BPF filter
  - Set the maximum number of packets, time, or length to sniff
  - Choose the time, size or packets to rotate the capture file
  - Select protocols to anonimize (IPv4,IPv6,MAC)
  - Select the method do anonimize each of the protocols (hash,map,zero,none)
  - Remove the payload from different protocols (IP,IPv6,TCP,UDP,ICMP,DNS)
  - Encrypt the capture files using GPG or ZIP with a password
  - Generate stadistics of the capture
  - Send the capture files via FTP, S3, WebDAV, SCP, SFTP, or to a web server
  - Integration with zabbix

## Instalation
1. Clone the repository
   ```bash
   git clone https://github.com/danipemos/sniffer.git
   cd sniffer
2. Execute the setup.sh script. This is script is made for Raspibian OS
   ```bash
   chmod +x setup.sh
   ./setup.sh
3. If you will use [sniffer-web](https://github.com/danipemos/sniffer-WEB) then change the /home/sniffer/config.ini file to add WEB and VPN parameters and execute:
   ```bash
   python access_web.py
## LICENSE
GNU General Public License v3.0 or later. See the [LICENSE](LICENSE) file for details.
