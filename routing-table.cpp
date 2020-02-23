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

#include "routing-table.hpp"
#include "core/utils.hpp"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
	//takes the destination IP from a packet and returns the routing table entry that gives the desired path.  
	//the destination in table may not be the destination you are looking for.  but it could have a similar prefix.  use algorithim to find longest prefix match
RoutingTableEntry
RoutingTable::lookup(uint32_t ip) const
{
	if (m_entries.empty())
	{
		throw std::runtime_error("Routing entry not found");
	}
	RoutingTableEntry longestMatchEntry;
	uint32_t longestMatchMask = 0;
	for (const auto& entry : m_entries) {

		//longest prefix match algorithm, assumes the routing table is formatted correctly.  

		if (entry.mask == 0) //mask of zero means this is a final hop, so it must be the destination we need, otherwise we can skip it.
		{
			if (entry.dest == ip)
			{
				return entry;
			}
			continue;
		}
		else 
		{
			uint32_t networkID = entry.dest & entry.mask; //bitwise operation that sets networkID to the portion of entry.dest that is the network portion. for example dest 192.55.233.50 and mask 255.255.0.0 makes the networkID 192.55.0.0 
			//cout << networkID;
			uint32_t mask_ip = ip & entry.mask;
			if ((networkID == mask_ip) && (entry.mask > longestMatchMask))
			{
				longestMatchEntry = entry;
				longestMatchMask = entry.mask;
			}
		}
		
	}
	if (longestMatchMask == 0)
	{
		throw std::runtime_error("Routing entry not found");
	}
	else
	{
		return longestMatchEntry;
	}
  // FILL THIS IN
	//for every entry in routing table
  //throw std::runtime_error("Routing entry not found");
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

//used to load/initialize the routing table from a file, default name of this file is RTABLE.  
bool
RoutingTable::load(const std::string& file)
{
  FILE* fp;
  char  line[BUFSIZ];
  char  dest[32];
  char  gw[32];
  char  mask[32];
  char  iface[32];
  struct in_addr dest_addr;
  struct in_addr gw_addr;
  struct in_addr mask_addr;

  if (access(file.c_str(), R_OK) != 0) {
    perror("access");
    return false;
  }

  fp = fopen(file.c_str(), "r");

  while (fgets(line, BUFSIZ, fp) != 0) {
    sscanf(line,"%s %s %s %s", dest, gw, mask, iface);
    if (inet_aton(dest, &dest_addr) == 0) {
      fprintf(stderr,
              "Error loading routing table, cannot convert %s to valid IP\n",
              dest);
      return false;
    }
    if (inet_aton(gw, &gw_addr) == 0) {
      fprintf(stderr,
              "Error loading routing table, cannot convert %s to valid IP\n",
              gw);
      return false;
    }
    if (inet_aton(mask, &mask_addr) == 0) {
      fprintf(stderr,
              "Error loading routing table, cannot convert %s to valid IP\n",
              mask);
      return false;
    }

    addEntry({dest_addr.s_addr, gw_addr.s_addr, mask_addr.s_addr, iface});
  }
  return true;
}

//used to add an entry to the routing table.  We should not need to use this.  It is used automatically in the function that loads the routing table.
void
RoutingTable::addEntry(RoutingTableEntry entry)
{
  m_entries.push_back(std::move(entry));
}

//overloads << operator so we can use cout to print a routing table entry.
std::ostream&
operator<<(std::ostream& os, const RoutingTableEntry& entry)
{
  os << ipToString(entry.dest) << "\t\t"
     << ipToString(entry.gw) << "\t"
     << ipToString(entry.mask) << "\t"
     << entry.ifName;
  return os;
}

//overloads << operator so we can use cout to print out the entire routing table.
std::ostream&
operator<<(std::ostream& os, const RoutingTable& table)
{
  os << "Destination\tGateway\t\tMask\tIface\n";
  for (const auto& entry : table.m_entries) {
    os << entry << "\n";
  }
  return os;
}

} // namespace simple_router
