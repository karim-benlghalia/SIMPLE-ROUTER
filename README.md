UCLA CS118 Project (Simple Router)
====================================
## TEAM
Brian Tagle : 604907076<br/>
Karim Benlghalia : 105179657

## Contribution
Brian worked on handling arp requests/replies in simple-router and the implementation of the routing table.
Karim worked on implementing handlePacket routine, IP handler routine and handling the ICMP packets.

## High Level Design
`simple-router`: This module receives packets at an interface and processes them.  When a packet is received the ethernet header is inspected to determine if it is an IP packet or an ARP packet.  If it is an ARP packet the arp handler function is used to determine if the ARP packet is an ARP reply or reuqest.  If it is an ARP request, the router formulates an ARP reply for the desired interface if it exists and sends the packet back to the requester.  If the packet is an ARP reply the router adds the given MAC-IP mapping to the arp cache and then sends out any packets who were waiting for this specific mapping. 

`Handle Packet` : Routine that receive the packet and inspect it. The handlePacket routine will ignore any packet that is not a broadcast, or not destined to the router. Also any packet that is not IPv4 or Arp will be ignored.

`IP handler routine`: After inspecting and determining that the type of the packet is an IP packet, the IP handler routine will be called to handle the packet. The handleIp routine extract the IP header from the packet and verify its checksum. If the checksum is valid, the routine proceed by handling the packet if not it will just ignore it. The routine will then proceed by decrementing the TTL, recalculating the checksum and inspecting the packet. If Its TTL is less than 0 or the packet is destined to the router, the routine will check if the packet carries an ICMP payload and dispache it properly. If the routine found that the packet needs to be forwarded, it will call the lookup routine to find the next-hop IP address in the routing table and attempt to forward it there. If not the request will be queued to be send later.

`ICMP reply and messages` : Routines that build an ICM messages based on the type of ICMP: Echo Reply message (type 0), Time Exceeded message (type 11, code 0), and Port Unreachable message (type 3, code 3).

`arp-cache`:

`routing-table`: Our team implemented the lookup portion of the routing table.  Lookup finds the next hop IP address by comparing the network ID portion of entries in the routing table with the network portion of the given target IP.  The network ID portion of the IP address is computed using the mask associated with the entry.  

## Problems encountered
One problem encountered was converting between host byte order and network byte order.  adding to the confusion, some things worked when no conversion was used while other things had to be converted manually between byte orders.  One example is in the ARP header where the hardware and protocol type had to be converted between byte orders while the hardware and protocol address length fields did not.  The best solution discovered for this was to look in the provided print functions in the core/utils file.  The implementation of these functions would show you what had to be converted and what did not.   

The problem that I encountered is getting segfault (and program crash) when implementing the the ICMP messages handler. This was caused by wrong calculation of the icmp header and the icmp payload. I had to figure out the correct size of the icmp header and the icmp payload to make it work. I also had difficulties figuring out which icmp messages we should deliver and when we should deliver them. I had mixed up all the icmp types and the icmp codes which made things more difficult for me to make the program work.
