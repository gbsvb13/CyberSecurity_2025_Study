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





