/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
void handleRequest(ArpRequest request) {
  
}

void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{
  // for each request in queued requests:
  // *         handleRequest(request)
  std::list<std::shared_ptr<ArpRequest>>::const_iterator request;
	for (request = m_arpRequests.begin(); request != m_arpRequests.end(); ) {
    // Handle request

    // Check to see if request has been made 5 times
    if ((*request)->nTimesSent >= MAX_SENT_TIME) {
      request = m_arpRequests.erase(request);
      continue;
    }

    // Create ARP request 
    Buffer packet(sizeof(ethernet_hdr) + sizeof(arp_hdr));
    ethernet_hdr* ethernet_header = (ethernet_hdr*) packet.data();
    arp_hdr* arp_header = (arp_hdr*) (packet.data() + sizeof(ethernet_hdr));

    const Interface* interface_id = m_router.findIfaceByName((*request)->packets.front().iface);
    // ETHER_ADDR_LEN = 6
    uint8_t Broadcast_adr[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    // Construct Ethernet header
    memcpy(ethernet_header->ether_shost, interface_id->addr.data(), ETHER_ADDR_LEN);
    memcpy(ethernet_header->ether_dhost, Broadcast_adr, ETHER_ADDR_LEN);
    ethernet_header->ether_type = htons(ethertype_arp);

    // ARP header
    arp_header->arp_hrd = htons(arp_hrd_ethernet);
    arp_header->arp_pro = htons(ethertype_ip);
    arp_header->arp_hln = ETHER_ADDR_LEN;
    arp_header->arp_pln = 4;
    arp_header->arp_op = htons(arp_op_request);
    memcpy(arp_header->arp_sha, interface_id->addr.data(), ETHER_ADDR_LEN);
    arp_header->arp_sip = interface_id->ip;
    memcpy(arp_header->arp_tha, Broadcast_adr, ETHER_ADDR_LEN);
    arp_header->arp_tip = (*request)->ip;  // might need to grab from the original packet (original dest IP)

    time_point current_time = steady_clock::now();
    (*request)->timeSent = current_time;
    (*request)->nTimesSent++;

    // Send reply
    m_router.sendPacket(packet, interface_id->name);
    std::cerr << "Amount of times this ARP request has been made " << (*request)->nTimesSent << std::endl;
    print_hdrs(packet);
    
    request++;
	}

  // for each cache entry in entries:
  // *         if not entry->isValid
  // *             record entry for removal
  // *     remove all entries marked for removal
  std::list<std::shared_ptr<ArpEntry>>::const_iterator entry;
  for (entry = m_cacheEntries.begin(); entry != m_cacheEntries.end(); ) {
    if ((*entry)->isValid) {
      entry++;
    } else {
      entry = m_cacheEntries.erase(entry);
    }
  }
  
  return;
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
