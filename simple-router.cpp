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

#include <fstream>

namespace simple_router
{

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void SimpleRouter::handlePacket(const Buffer &packet, const std::string &inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface *iface = findIfaceByName(inIface);
  if (iface == nullptr)
  {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

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
      break;
    case ethertype_arp: //handle ARP packet.
      std::cout << "This an ARP packet" << std::endl;
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
