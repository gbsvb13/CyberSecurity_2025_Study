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







