/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/***
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"
#include <string>
#include <fstream>

namespace simple_router
{

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
std::string G_interface;
void SimpleRouter::handlePacket(const Buffer &packet, const std::string &inIface)
{
  //std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;
  G_interface = inIface;
  const Interface *iface = findIfaceByName(inIface);
  if (iface == nullptr)
  {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }
  //std::cerr << "Received Packet:" << std::endl;
  //print_hdrs(packet);
  //std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN

  //  ****************    HandlePacket function requirements *********************************************************************************************************
  //Check Ethernet frames, and ignore  Ethernet frames not destined to the router(destination hardware address is neither the corresponding
  // MAC address of the interface nor a broadcast address)
  //Everytime The router receive an ehernet frame, we need to check the type of its payload if its IP4 or ARP, and ignore Ethernet frames other than ARP and IPv4.
  //If it is IP4 we need to do the Sanity-check the packet (meets minimum length and has correct checksum).
  //Decrement the TTL by 1, and recompute the packet checksum over the modified header.
  //Find out which entry in the routing table has the longest prefix match with thedestination IP address.
  //Check the ARP cache for the next-hop MAC address corresponding to the next-hop IP. If it’s there, send it. Otherwise, send an ARP request for the
  //next-hop IP (if one hasn’t been sent within the last second), and add the packet to the queue of packets waiting on this ARP request.
  //If the IP packet is destined towards one of our router’s IP addresses then:
  //                            * If the packet is an ICMP echo request and its checksum is valid, send an ICMP
  //                               echo reply to the sending host.
  //                             * If the packet contains a TCP or UDP payload, send an ICMP port unreachable to
  //                                the sending host. Otherwise, ignore the packet. Packets destined elsewhere
  //                                should be forwarded using your normal forwarding logic.
  // *******************************************************************************************************************************************************************

  // If the payload type is an IP4 then:
  //             * Extract the IP4 header from the ethernet frame Get Ip adresses .
  //             * sanity check minimum length and correct checksum
  //             * use the lookup function to find the MAC adress of the next-hop destination in the ARP cache
  //             * If it is not in the ARP cache then we should queue the received packet and send ARP request to discover the IP-MAC mapping.
  //             * If it is in the ARP cache then the router should proceed with handling the IP packet by modifying the MAC addresses in Ethernet frame
  //                and send the packet to the corresponding next-hop IP.

  //If the payload is an ARP then:
  //             * Extract the ARP header from the ethernet frame Get Ip adresses .
  //             * check if the ARP is a request or a reply.
  //             * If it is a request:  properly respond to ARP requests for MAC address for the IP.
  //             * If it is a reply:  record IP-MAC mapping information in ARP cache (Source IP/Source hardware address in the ARP reply), and send
  //               out all corresponding enqueued packets.
  //             * Ignore all the ARP requests.

  // Handles ICMP still working on it.

  struct ethernet_hdr hdr_ether;

  //get the ethernet header basically the first 14 bytes (6 bytes for destination address, 6 bytes for the source address, and 2 bytes for ethernet type ),
  memcpy(&hdr_ether, packet.data(), sizeof(hdr_ether));
  uint16_t eth_type = ntohs(hdr_ether.ether_type);

  uint8_t Broadcast_adr[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

  // check if the packet is sent to the router or it is a broadcast packet
  if ((memcmp(hdr_ether.ether_dhost, Broadcast_adr, 6) == 0) ||
      (memcmp(hdr_ether.ether_dhost, (iface->addr.data()), 6) == 0))
  {

    switch (eth_type)
    {
    case ethertype_ip: // handle ip packet
      std::cout << "This an IP packet" << std::endl;
	  print_hdrs(packet);
      handleIP(packet, hdr_ether);
      break;
    case ethertype_arp: //handle ARP packet.
      std::cout << "This an ARP packet" << std::endl;
      handleARP(packet);
      break;
    default:
      //the packet is not an ARP nor IP packet it should be ignored.
      std::cerr << "Packet is not an IP nor an ARP, ignoring" << std::endl;
      return;
    }
  }

  else
  {

    //ignore Ethernet frames not destined to the router or are not a broadcast.
    std::cerr << "Frame is not destined to router (i.e. Neither the corresponding MAC address of the interface nor a broadcast address), ignoring" << std::endl;
    return;
  }
  
}

void SimpleRouter::handleIP(const Buffer &packet, struct ethernet_hdr &e_hdr)
{

  
  const Interface *R_Interface;
  struct ip_hdr ip_header;

  if (packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr))
  {
    std::cerr << "Invalid minimum length of IP packet, ignoring" << std::endl;
    return;
  }

  memcpy(&ip_header, packet.data() + sizeof(ethernet_hdr), sizeof(ip_header));

  struct ip_hdr ip_header_copy;
  memcpy(&ip_header_copy, &ip_header, sizeof(ip_header));
  ip_header_copy.ip_sum = 0;
  //verify the packet checksum
  uint16_t cksum_check = cksum(&ip_header_copy, sizeof(ip_header_copy));

  if (cksum_check == (ip_header.ip_sum))
  {
    ip_header.ip_ttl = ip_header.ip_ttl - 1;
    ip_header.ip_sum = 0;
    ip_header.ip_sum = cksum(&ip_header, sizeof(ip_header)); //Recompute checksum
    Buffer Dup_packet = packet;
    uint32_t temp_dest_ip;
    memcpy(&temp_dest_ip, &packet[30], sizeof(temp_dest_ip));
    if (ip_header.ip_ttl <= 0)
    {
      /*
      *****************   TO DO: Do NOt forget to implement This! **********************************************
    construct a Time Exceeded ICMP message to reply.
      
      */

      // call ICMP handler that send an ICMP reply
      uint16_t Scksum = cksum(packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header), (int)sizeof(packet) - ICM_padding);
      if (Scksum == VALID_S) //valid ICMP packet
      {
        struct icmp_hdr icmp_header;
        memcpy(&icmp_header, packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header), sizeof(icmp_header));

        uint8_t icmp_type = 0x0b;
        uint8_t icmp_code = 0x00;

        if (icmp_header.icmp_type == 8) //ICMP echo message
        {

          buildIcm_reply(Dup_packet, e_hdr, icmp_type);
        }
        else
        {

          if (findIfaceByIp(temp_dest_ip) != nullptr)
          {
            icmp_type = 0x03;
            icmp_code = 0x03;
            HandleIcmMessage(packet, e_hdr, icmp_type, icmp_code);
          }
          else
            HandleIcmMessage(packet, e_hdr, icmp_type, icmp_code);
        }
      }
    }
    R_Interface = findIfaceByIp(ip_header.ip_dst);

    if (R_Interface != nullptr)
    {
      /*
      *****************   TO DO: Do NOt forget to implement This! **********************************************
    If the packet is an ICMP echo request and its checksum is valid, send an ICMP echo reply to the sending host.
    If the packet contains a TCP or UDP payload, send an ICMP port unreachable to the sending host. Otherwise, 
    ignore the packet. Packets destined elsewhere should be forwarded using your normal forwarding logic.
      
      */
      //may be ICMP packet
      // call ICMP handler

      //may be ICMP packet

      if (ip_header.ip_p == 0x01) //ICMP message
      {
        
        struct icmp_hdr icmp_header;
        memcpy(&icmp_header, packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header), sizeof(icmp_header));

        if (icmp_header.icmp_type == 8) //ICMP echo message
        {
          uint8_t icmp_type = 0x00;
          buildIcm_reply(Dup_packet, e_hdr, icmp_type);
        }
      }
      else if (ip_header.ip_p == 0x11 || ip_header.ip_p == 0x06) //TCP/UDP Protocol

      {
        
        struct icmp_hdr icmp_header;
        memcpy(&icmp_header, packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header), sizeof(icmp_header));

        if (icmp_header.icmp_type == 8) //ICMP echo message
        {
          uint8_t icmp_type = 0x0b;
          buildIcm_reply(Dup_packet, e_hdr, icmp_type);
        }

        else
        {
          uint8_t icmp_type = 0x0b;
          uint8_t icmp_code = 0x00;
          if (findIfaceByIp(temp_dest_ip) != nullptr)
          {
            icmp_type = 0x03;
            icmp_code = 0x03;
            HandleIcmMessage(packet, e_hdr, icmp_type, icmp_code);
          }
          else
            HandleIcmMessage(packet, e_hdr, icmp_type, icmp_code);
        }
      }
    }
	else
	{
		RoutingTableEntry RT_Entry;
		try 
		{
			RT_Entry = m_routingTable.lookup(ip_header.ip_dst);
		}
		catch(...)
		{
			 //if not found in forwarding table
				std::cout << " No match in forwarding table found!\n"
					<< std::endl;
				return;
			
		}
      const Interface *F_Interface = findIfaceByName(RT_Entry.ifName);
      std::shared_ptr<simple_router::ArpEntry> dest_mac;
      if (m_arp.lookup(ip_header.ip_dst) != nullptr)
      {
   
          std::string matched_mac = ipToString(RT_Entry.dest);
          dest_mac = m_arp.lookup(ip_header.ip_dst);

          memcpy(e_hdr.ether_shost, F_Interface->addr.data(), sizeof(e_hdr.ether_shost));
          memcpy(e_hdr.ether_dhost, (dest_mac->mac).data(), sizeof(e_hdr.ether_dhost));

          memcpy(const_cast<unsigned char *>(packet.data()), &e_hdr, sizeof(e_hdr));
          memcpy((const_cast<unsigned char *>(packet.data() + sizeof(e_hdr))), &ip_header, sizeof(ip_header));
          sendPacket(packet, RT_Entry.ifName); //send packet
          //print_hdrs(packet);
        
 
      }
      else
      {
        // Queue the request to send later
        Buffer ip_and_data(packet.begin() + sizeof(ethernet_hdr), packet.end()); //QUEUE only ip hdr and payload, not ethernet because the arp handler code expects no ethernet header.
		std::cerr << "queueing IP packet" << std::endl;
        std::shared_ptr<ArpRequest> arp_request = m_arp.queueRequest(ip_header.ip_dst, ip_and_data, F_Interface->name);
        std::cout << "Next-hop IP not in ARP Cache, queuing ARP request" << std::endl;
      }

    } ////****************
  }
  else
  {
    std::cerr << "Invalid checksum, ignoring" << std::endl;
    return;
  }
}

void SimpleRouter::buildIcm_reply(Buffer &Dup_packet, struct ethernet_hdr &e_hdr, uint8_t icmp_type)
{
  struct icmp_hdr icmp_header;
  struct ip_hdr ip_header;
  struct ethernet_hdr e_header;
  memcpy(&e_header, Dup_packet.data(), sizeof(ethernet_hdr));
  memcpy(&ip_header, Dup_packet.data() + sizeof(ethernet_hdr), sizeof(ip_hdr));
  int padding = (int)(sizeof(Dup_packet) - sizeof(ethernet_hdr) - sizeof(ip_hdr));
  memcpy(&icmp_header, Dup_packet.data() + sizeof(e_header) + (ip_header.ip_hl * 4), sizeof(icmp_header));

  //ICMP Layer
  uint16_t cKsum_ICM = cksum(&icmp_header, padding);
  memcpy(Dup_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header), &icmp_type, sizeof(icmp_type));
  memcpy(Dup_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header) + 2, &cKsum_ICM, sizeof(icmp_header.icmp_sum));

  //IP layer
  const Interface *R_RInterface = findIfaceByName(G_interface);
  uint32_t temp_src_ip;

  bzero(Dup_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header) - 10, sizeof(uint8_t));
  uint8_t cKsum_IP = cksum(Dup_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header) - 20, sizeof(ip_hdr));
  memcpy(Dup_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header) - 10, &cKsum_IP, sizeof(cKsum_IP));
  memcpy(&temp_src_ip, Dup_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header) - 4, sizeof(temp_src_ip));
  memcpy(Dup_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header) - 4, &Dup_packet[26], sizeof(temp_src_ip));
  memcpy(Dup_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header) - 8, &temp_src_ip, sizeof(temp_src_ip));

  //Ethernet layer
  memcpy(Dup_packet.data(), Dup_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header) - 28, sizeof(e_hdr.ether_shost));
  memcpy(Dup_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header) - 28, &R_RInterface->addr[0], sizeof(e_hdr.ether_shost));

  sendPacket(Dup_packet, R_RInterface->name);
  std::cout << "*****send ICMP packet*****" << std::endl;
  //print_hdrs(Dup_packet);
}

void SimpleRouter::HandleIcmMessage(const Buffer &packet, struct ethernet_hdr &e_hdr, uint8_t icmp_type, uint8_t icmp_code)
{
  Buffer ICM_packet;
  uint8_t ip_protocol;
  struct ip_hdr ip_header;
  memcpy(&ip_header, packet.data() + sizeof(ethernet_hdr), sizeof(ip_hdr));
  memcpy(&ip_protocol, packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header) - 11, sizeof(ip_protocol));

  struct icmp_hdr icmp_header;
  memcpy(&icmp_header, packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header), sizeof(icmp_header));

  ICM_packet = std::vector<unsigned char>(70);

  memcpy(ICM_packet.data(), packet.data(), ICM_padding);
  memcpy(ICM_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header) + 8, packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header) - 20, 28);
  uint32_t temp_dest_ip;
  memcpy(&temp_dest_ip, packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header) - 4, sizeof(temp_dest_ip));

  memcpy(ICM_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header), &icmp_type, sizeof(icmp_type));
  memcpy(ICM_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header) + 1, &icmp_code, sizeof(icmp_code));
  uint16_t cKsum_ICM = cksum(ICM_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header), ICM_packet.size() - ICM_padding);
  memcpy(ICM_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header) + 2, &cKsum_ICM, sizeof(icmp_header.icmp_sum));

  //IP layer
  const Interface *R_Rinterface = findIfaceByName(G_interface);
  uint32_t temp_src_ip;
  ip_protocol = 0x01;
  uint16_t ip_length;
  memcpy(&ip_length, ICM_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header) - 18, sizeof(ip_length));
  ip_length = htons(ntohs(ip_length) - 0x04);

  bzero(ICM_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header) - 10, sizeof(uint16_t));

  memcpy(ICM_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header) - 11, &ip_protocol, sizeof(ip_protocol));
  memcpy(ICM_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header) - 18, &ip_length, sizeof(uint16_t));

  if (findIfaceByIp(temp_dest_ip) != nullptr)
    memcpy(&temp_src_ip, &temp_dest_ip, sizeof(temp_src_ip));
  else
    memcpy(&temp_src_ip, &R_Rinterface->ip, sizeof(temp_src_ip));
  memcpy(ICM_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header) - 4, ICM_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header) - 8, sizeof(temp_src_ip));
  memcpy(ICM_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header) - 8, &temp_src_ip, sizeof(temp_src_ip));

  uint16_t cKsum_IP = cksum(ICM_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header) - 20, sizeof(ip_hdr));
  memcpy(ICM_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header) - 10, &cKsum_IP, sizeof(cKsum_IP));

  //Ethernet layer
  memcpy(ICM_packet.data(), ICM_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header) - 28, sizeof(e_hdr.ether_shost));
  memcpy(ICM_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_header) - 28, &R_Rinterface->addr[0], sizeof(e_hdr.ether_shost));
  sendPacket(ICM_packet, R_Rinterface->name);
  std::cout << "*****send ICMP packet*****" << std::endl;
}

void SimpleRouter::handleARP(const Buffer &packet)
{
  const uint8_t *buf = packet.data() + 14;
  struct arp_hdr *hdr_arp = (arp_hdr *)buf;

  if (ntohs(hdr_arp->arp_hrd) != arp_hrd_ethernet) //hardware type is 0x0001 (ethernet)
  {
    std::cerr << "Packet hardware type is not supported" << std::endl;
    return;
  }
  if (ntohs(hdr_arp->arp_pro) != ethertype_ip) //protocol type is 0x0800 (IPv4)
  {
    std::cerr << "Packet protocol type is not supported" << std::endl;
    return;
  }
  if (hdr_arp->arp_hln != 0x06) //hardware address length
  {
    std::cerr << "Length of specified hardware address is not supported" << std::endl;
    return;
  }
  if (hdr_arp->arp_pln != 0x04) //protocol address length
  {
    std::cerr << "Length of specified network address is not supported" << std::endl;
    return;
  }

  //record mac->IP mapping, we only have to do this for replies, but we can optionally do it for requests as well.
  const Buffer mac(hdr_arp->arp_sha, hdr_arp->arp_sha + ETHER_ADDR_LEN);
  std::shared_ptr<ArpRequest> pending_Requests = m_arp.insertArpEntry(mac, hdr_arp->arp_sip);

  switch (ntohs(hdr_arp->arp_op))
  {
  case arp_op_request: //arp request message
  {
    const Interface *face = findIfaceByIp(hdr_arp->arp_tip); //looking for hardware interface with corresponding ip address
    if (face != nullptr)
    {
      ////////////////////////////////////
      ////////ARP HEADER TO SEND//////////
      ////////////////////////////////////
      struct arp_hdr *hdr_arp_SEND;
      hdr_arp_SEND = (struct arp_hdr *)malloc(sizeof(arp_hdr));
      memcpy(hdr_arp_SEND, hdr_arp, sizeof(arp_hdr));

      hdr_arp_SEND->arp_op = htons(arp_op_reply);

      //source hardware address is the interface with the requested mac address
      for (int pos = 0; pos < ETHER_ADDR_LEN; pos++)
      {
        hdr_arp_SEND->arp_sha[pos] = (face->addr.data())[pos];
      }
      //memcpy(hdr_arp_SEND->arp_sha, face->addr.data(), sizeof(hdr_arp_SEND->arp_sha));
      hdr_arp_SEND->arp_sip = face->ip;

      //destination hardware address is the source hardware address of the ARP request
      for (int pos = 0; pos < ETHER_ADDR_LEN; pos++)
      {
        hdr_arp_SEND->arp_tha[pos] = (hdr_arp->arp_sha)[pos];
      }
      hdr_arp_SEND->arp_tip = hdr_arp->arp_sip;

      ////////////////////////////////////
      //////ETHERNET HEADER TO SEND///////
      ////////////////////////////////////
      struct ethernet_hdr *eth_hdr_SEND;
      eth_hdr_SEND = (struct ethernet_hdr *)malloc(sizeof(struct ethernet_hdr));

      RoutingTableEntry RT_entry = m_routingTable.lookup(hdr_arp->arp_sip);

      std::shared_ptr<ArpEntry> ARP_entry = m_arp.lookup(RT_entry.gw);
      if (ARP_entry == nullptr)
      {
        std::cerr << "ARP_entry is nullptr" << std::endl;
      }

      for (int pos = 0; pos < ETHER_ADDR_LEN; pos++)
      {
        eth_hdr_SEND->ether_dhost[pos] = (ARP_entry->mac.data())[pos];
      }

      const Interface *face_SEND = findIfaceByName(RT_entry.ifName);
      for (int pos = 0; pos < ETHER_ADDR_LEN; pos++)
      {
        eth_hdr_SEND->ether_shost[pos] = (face_SEND->addr.data())[pos];
      }
      eth_hdr_SEND->ether_type = htons(ethertype_arp);

      buf = (const uint8_t *)eth_hdr_SEND;
      const Buffer packet_TEMP_ETHER(buf, buf + sizeof(struct ethernet_hdr));

      buf = (const uint8_t *)hdr_arp_SEND;
      const Buffer packet_TEMP_ARP(buf, buf + sizeof(struct arp_hdr));

      Buffer packet_SEND;
      packet_SEND.insert(packet_SEND.begin(), packet_TEMP_ETHER.begin(), packet_TEMP_ETHER.end());
      packet_SEND.insert(packet_SEND.end(), packet_TEMP_ARP.begin(), packet_TEMP_ARP.end());

      //std::cerr << "Sent Packet:" << std::endl;
      //print_hdrs(packet_SEND);

      sendPacket(packet_SEND, face_SEND->name);
      free(hdr_arp_SEND);
      free(eth_hdr_SEND);
    }
  }
  break;
  case arp_op_reply:
  { //arp reply message, ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip), //using Buffer = std::vector<unsigned char>;
    if (pending_Requests == nullptr)
    {
      std::cerr << "no pending requests associated with this arp reply" << std::endl;
	  
    }
    else
    {
      for (const auto &request : pending_Requests->packets) //ASSUMES THE REQUEST
      {

        ////////////////////////////////////
        //////ETHERNET HEADER TO SEND///////
        ////////////////////////////////////
        struct ethernet_hdr *eth_hdr_SEND;
        eth_hdr_SEND = (struct ethernet_hdr *)malloc(sizeof(struct ethernet_hdr));

        for (int pos = 0; pos < ETHER_ADDR_LEN; pos++)
        {
          eth_hdr_SEND->ether_dhost[pos] = (hdr_arp->arp_sha)[pos]; //TODO FIX
        }

        const Interface *face_SEND = findIfaceByName(request.iface);
        for (int pos = 0; pos < ETHER_ADDR_LEN; pos++)
        {
          eth_hdr_SEND->ether_shost[pos] = (face_SEND->addr.data())[pos]; //get the hardware address of the outface specified by this request
        }
        eth_hdr_SEND->ether_type = htons(ethertype_ip);

        buf = (const uint8_t *)eth_hdr_SEND;
        Buffer packet_SEND(buf, buf + sizeof(struct ethernet_hdr)); //insert ethernet header

        packet_SEND.insert(packet_SEND.end(), request.packet.begin(), request.packet.end()); //insert payload (ipv4)
        sendPacket(packet_SEND, face_SEND->name);
		std::cerr << "unqueueing and sending IP packet:" << std::endl;
		
        free(eth_hdr_SEND);
      }
      m_arp.removeRequest(pending_Requests);
    }
    //TODO do all packets in the queue get removed when n=5 (times sent)?  ALSO remove packets from queue once we get a reply
  }
  break;
  default: //op code not recognized
    std::cerr << "op code not recognized" << std::endl;
    return;
  }
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
    : m_arp(*this)
{
}

void SimpleRouter::sendPacket(const Buffer &packet, const std::string &outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool SimpleRouter::loadRoutingTable(const std::string &rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void SimpleRouter::loadIfconfig(const std::string &ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line))
  {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0)
    {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void SimpleRouter::printIfaces(std::ostream &os)
{
  if (m_ifaces.empty())
  {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto &iface : m_ifaces)
  {
    os << iface << "\n";
  }
  os.flush();
}

const Interface *
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip](const Interface &iface) {
    return iface.ip == ip;
  });

  if (iface == m_ifaces.end())
  {
    return nullptr;
  }

  return &*iface;
}

const Interface *
SimpleRouter::findIfaceByMac(const Buffer &mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac](const Interface &iface) {
    return iface.addr == mac;
  });

  if (iface == m_ifaces.end())
  {
    return nullptr;
  }

  return &*iface;
}

void SimpleRouter::reset(const pox::Ifaces &ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto &iface : ports)
  {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end())
    {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

const Interface *
SimpleRouter::findIfaceByName(const std::string &name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name](const Interface &iface) {
    return iface.name == name;
  });

  if (iface == m_ifaces.end())
  {
    return nullptr;
  }

  return &*iface;
}

} // namespace simple_router
