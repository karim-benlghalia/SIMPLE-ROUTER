UCLA CS118 Project (Simple Router)
====================================
## TEAM
Brian Tagle : 604907076

## Contribution
Brian worked on handling arp requests/replies in simple-router and the implementation of the routing table.

## High Level Design
`simple-router`: This module receives packets at an interface and processes them.  When a packet is received the ethernet header is inspected to determine if it is an IP packet or an ARP packet.  If it is an ARP packet the arp handler function is used to determine if the ARP packet is an ARP reply or reuqest.  If it is an ARP request, the router formulates an ARP reply for the desired interface if it exists and sends the packet back to the requester.  If the packet is an ARP reply the router adds the given MAC-IP mapping to the arp cache and then sends out any packets who were waiting for this specific mapping. 

`arp-cache`:

`routing-table`: Our team implemented the lookup portion of the routing table.  Lookup finds the next hop IP address by comparing the network ID portion of entries in the routing table with the network portion of the given target IP.  The network ID portion of the IP address is computed using the mask associated with the entry.  

## Problems encountered
One problem encountered was converting between host byte order and network byte order.  adding to the confusion, some things worked when no conversion was used while other things had to be converted manually between byte orders.  One example is in the ARP header where the hardware and protocol type had to be converted between byte orders while the hardware and protocol address length fields did not.  The best solution discovered for this was to look in the provided print functions in the core/utils file.  The implementation of these functions would show you what had to be converted and what did not.   