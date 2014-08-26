/*	sdns
	Copyright (C) 2012-2014 David Geib, Trustiosity LLC
	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License Version 3
	(AGPLv3) with the following Supplemental Terms:

	A. Supplemental Terms. These supplemental terms are a part of the agreement
	and are not "further restrictions" under the AGPLv3. All licensees
	including all downstream licensees are subject to these supplemental terms.
	These supplemental terms also apply to anyone who propagates, receives or
	runs a copy of the Program notwithstanding Section 9 of the AGPLv3. 

	B. Governing Law; Venue. The laws of the State of Connecticut and the
	federal laws of the United States of America, without reference to conflict
	of law rules, govern this agreement and any dispute of any sort that might
	arise regarding this agreement or the Software. Any dispute relating in any
	way to this agreement or the Software where a party seeks aggregate relief
	of $500 or more, or an injunction or similar equitable relief, will be
	adjudicated in any state or federal court located in the State of
	Connecticut. You consent to exclusive jurisdiction and venue in those
	courts. The United Nations Convention for the International Sale of Goods
	does not apply to this agreement. 

	C. Export. You may not export the Software into any country or jurisdiction
	or receive or use the Software in any country or jurisdiction if doing so
	would be a violation of applicable law or could cause any licensor to be
	subject to civil or criminal liability or penalties in that or another
	country or jurisdiction. For example, you may not export the Software if
	doing so would violate United States Export Administration Regulations or
	International Traffic in Arms Regulations, or if the Software would
	infringe a proprietary right of a third party that is recognized in the
	jurisidiction in question. 

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#ifndef CACHE_H
#define CACHE_H
#include "dns_message.h"


struct ncache_soa {
	std::unique_ptr< dns_record<soa_rdata> > soa;
	bool nxdomain; // NXDOMAIN vs. NODATA
	ncache_soa(domain_name && name, soa_rdata && soa_r, ttlexp expire, bool nx)
		: soa(new dns_record<soa_rdata>(std::move(name), dns_type_t::SOA, dns_class_t::IN, expire, std::move(soa_r))), nxdomain(nx) {}
	ncache_soa() : nxdomain(false) {}
};

// dcache is based on djb's excellent public domain cache implementation from dnscache; why reinvent the wheel?
class dcache
{
	/*
	1024 <= size <= 1024*1024*1024.
	4 <= hsize <= size/16.
	hsize is a power of 2.
	
	hsize <= writer <= oldest <= unused <= size.
	If oldest == unused then unused == size.
	
	cache is a hash table with the following structure:
	cache[0...hsize-1]: hsize/4 head links.
	cache[hsize...writer-1]: consecutive entries, newest entry on the right.
	cache[writer...oldest-1]: free space for new entries.
	cache[oldest...unused-1]: consecutive entries, oldest entry on the left.
	cache[unused...size-1]: unused.
	
	Each hash bucket is a linked list containing the following items:
	the head link, the newest entry, the second-newest entry, etc.
	Each link is a 4-byte number giving the xor of
	the positions of the adjacent items in the list.
	
	Entries are always inserted immediately after the head and removed at the tail.
	
	Each entry contains the following information:
	4-byte link; 1-byte rrset type; 1-byte key len; 2-byte rrset len; 8-byte expire time; key; rrset
	*/
	uint8_t* cache;
	uint32_t size;
	uint32_t hsize;
	uint32_t writer;
	uint32_t oldest;
	uint32_t unused;
	static const size_t MAXKEYLEN;
	static const size_t MAXDATALEN;
	static const size_t HDRLEN;
	static void cache_impossible() {
		eout() << "DNS cache assertion failure, program terminated";
		abort();
	}
	template<class T>
	void set(uint32_t pos, T u) const
	{
		if(pos > size - sizeof(u)) cache_impossible();
		memcpy(cache + pos, &u, sizeof(u));
	}
	template<class T>
	T get(uint32_t pos) const
	{
		if(pos > size - sizeof(T)) cache_impossible();
		T result;
		memcpy(&result, cache + pos, sizeof(result));
		return result;
	}
	unsigned int hash(const uint8_t *key, unsigned int keylen) const;
	struct cache_entry
	{
		const uint8_t* ptr;
		cache_entry(uint8_t* p) : ptr(p) {}
		template<class T> T get(const uint8_t* p) { T rv; memcpy(&rv, p, sizeof(rv)); return rv; }
		bool entry_exists() const { return ptr != nullptr; }
		dns_type_t get_type() { return ptr ? dns_type_t(ptr[4]) : dns_type_t::INVALID; }
		unsigned get_keylen() { return ptr ? ptr[5] : 0; }
		size_t get_datalen() { return ptr ? get<uint16_t>(ptr+6) : 0; }
		uint64_t get_expiration() { return ptr ? get<uint64_t>(ptr+8) : 0; }
		const uint8_t * get_data() { return ptr ? (ptr+HDRLEN+get_keylen()) : nullptr; }
	};
	cache_entry cache_get(const uint8_t *key, unsigned int keylen, dns_type_t tp, size_t *datalen, uint64_t *ttl) const;
	void cache_set(const uint8_t *key, unsigned int keylen, const rrset_data & rrset);
	static void copy_entry(const uint8_t * data, size_t datalen, rrset_data & rrset);
public:
	dcache();
	~dcache() { delete[] cache; }
	bool contains_record(const domain_name & name, dns_type_t tp) const;
	std::unique_ptr<rrset_data> get_rrset(const domain_name & name, dns_type_t tp) const;
	template<class RDATA> rrset_rdata<RDATA> get_rrset(const domain_name& name) const;
	void cache_rrset(const domain_name & name, const rrset_data & rrset) { cache_set(name.cache_get(), name.cache_size(), rrset); }
	
	// ncache: negative cache, see RFC2308
	// notably, when caching NXDOMAIN, reply should be sent with SOA for the zone in authority sec. (which carries "minimum" TTL) b/c NXDOMAIN has no explicit TTL
	// NXDOMAIN (rcode=name error) means the name does not exist in the specified class
	// NODATA means that no record of the specified type exists in the specified class for that name
		// NODATA is not an rcode, it is just the absence of any record; RFC2308 recommends not sending it with anything in NS section to avoid confusion with referrals
	void ncache_nodata(const domain_name & name, dns_type_t tp, const domain_name & soa_name, const rrset_rdata<soa_rdata> & soa);
	void ncache_nx(const domain_name & name, const domain_name & soa_name, const rrset_rdata<soa_rdata> & soa, bool nxdomain = true);
	ncache_soa get_ncache_soa(const domain_name & name);
};

template<class RDATA> rrset_rdata<RDATA> dcache::get_rrset(const domain_name& name) const {
	size_t datalen;
	rrset_rdata<RDATA> rrset(RDATA::get_type(), dns_class_t::IN, ttlexp());
	cache_entry entry = cache_get(name.cache_get(), name.cache_size(), RDATA::get_type(), &datalen, &rrset.expire.ttl);
	if(!entry.entry_exists()) return rrset;
	copy_entry(entry.get_data(), datalen, rrset);
	return std::move(rrset);
}

class pcache
{
	struct pcache_rrset {
		std::unique_ptr<rrset_data> rr;
		pcache_rrset(const rrset_data & rrset) : rr(rrset.clone()) {}
	};
	struct pcache_records {
		std::vector<pcache_rrset> rrsets; // unsorted
	};
	std::unordered_map<domain_name, pcache_records> cache;
public:
	void cache_rrset(const domain_name &name, const rrset_data& rrset);
	bool contains_record(const domain_name & name, dns_type_t tp, dns_class_t cl = dns_class_t::IN) const { return get_rrset(name, tp, cl).record_count() > 0; }
	const rrset_data & get_rrset(const domain_name &name, dns_type_t tp, dns_class_t cl) const;
	void read_record_file(const std::string & filename);
	void clear_records() { cache.clear(); }
};


class dns_cache
{
	pcache static_cache;
	dcache dynamic_cache;
	bool ns_has_address(const ns_rdata &ns, dns_type_t ip_types[], size_t num_ip_types) const;
	template<class IP_RDATA>
	bool ns_addr_match_rdata(const ns_rdata &name, const sockaddrunion &fromaddr);
public:
	struct closest_ns {
		std::vector<ns_rdata> ns;
		unsigned depth;
		closest_ns(std::vector<ns_rdata> n, unsigned d) : ns(std::move(n)), depth(d) {}
	};
	// note: this get_closest_ns() doesn't provide forwarders, use get_closest_ns() in dns_query_init for that
	closest_ns get_closest_ns(const domain_name &name, int use_ip_family) const;
	//note: ns_in_bailiwick checks if fromaddr is a valid authoritative nameserver for name, but does not check forwarders, use in_bailiwick in dns_query_init for that
	bool ns_in_bailiwick(const domain_name &name, const sockaddrunion &fromaddr);
	bool ns_addr_match(const ns_rdata &name, const sockaddrunion &fromaddr);
	// get_rrset gives rrset_[r]data, the rrset was in cache if record_count() > 0
	// if rrset_data is non-nullptr and TTL is not expired but there are no records, cached record was negative-cached NODATA
	template<class RDATA> rrset_rdata<RDATA> get_rrset(const domain_name &name) const;
	std::unique_ptr<rrset_data> get_rrset(const domain_name &name, dns_type_t tp, dns_class_t cl = dns_class_t::IN) const;

	struct cname_loop_exception {};
	std::vector< dns_record<cname_rdata> > follow_cname(domain_name target_name, rrset_rdata<cname_rdata> cname) const; // throws cname_loop_exception
	// same as get_rrset() but follows CNAME chains for non-CNAME types
	template<class RDATA> rrset_rdata<RDATA> get_rrset_target(const domain_name &cname) const;

	void cache_rrset(const domain_name & name, const rrset_data * rrset, bool force = false);
	void cache_rrset(const dns_rrset & rrset) { cache_rrset(rrset.get_name(), rrset.rrdata.get()); }
	void cache_rrset_static(const domain_name & name, const rrset_data * rrset);
	void cache_rrset_static(const dns_rrset & rrset) { cache_rrset_static(rrset.get_name(), rrset.rrdata.get()); }
	void ncache_nodata(const domain_name & name, dns_type_t tp, dns_class_t cl, const domain_name & soa_name, const rrset_rdata<soa_rdata> & soa)
		{ if(cl == dns_class_t::IN) dynamic_cache.ncache_nodata(name, tp, soa_name, soa); }
	void ncache_nxdomain(const domain_name & name, dns_class_t cl, const domain_name & soa_name, const rrset_rdata<soa_rdata> & soa)
		{ if(cl == dns_class_t::IN) dynamic_cache.ncache_nx(name, soa_name, soa); }
	ncache_soa get_ncache_soa(const domain_name & name) { return dynamic_cache.get_ncache_soa(name); }
	bool contains_record(const domain_name & name, dns_type_t tp, dns_class_t cl = dns_class_t::IN);

	void read_record_file(const std::string & filename) { static_cache.read_record_file(filename); }
	void clear_static_records() { static_cache.clear_records(); }
};

template<class RDATA> rrset_rdata<RDATA> dns_cache::get_rrset(const domain_name &name) const
{
	const rrset_data &r = static_cache.get_rrset(name, RDATA::get_type(), dns_class_t::IN);
	if(r.get_type() == RDATA::get_type() && r.record_count() > 0) {
		rrset_rdata<RDATA> rr(r.get<RDATA>());
		rr.expire.ttl += ttlexp::now();
		return std::move(rr);
	}
	return dynamic_cache.get_rrset<RDATA>(name);
}

// CNAME template specialization for get_rrset_target is intentionally declared but never defined because any attempt to use it is almost certainly in error
template<> rrset_rdata<cname_rdata> dns_cache::get_rrset_target<cname_rdata>(const domain_name &cname) const;
// commented below is the sensible implementation if it should ever be required
//template<> rrset_rdata<cname_rdata> inline dns_cache::get_rrset_target<cname_rdata>(const domain_name &cname) const { return get_rrset<cname_rdata>(cname); }

template<class RDATA> rrset_rdata<RDATA> dns_cache::get_rrset_target(const domain_name &cname) const {
	rrset_rdata<cname_rdata> next = get_rrset<cname_rdata>(cname);
	if(next.record_count() == 0)
		return get_rrset<RDATA>(cname);
	domain_name loop_check = cname;
	rrset_rdata<cname_rdata> last(dns_type_t::INVALID, dns_class_t::INVALID, ttlexp());
	size_t count = 1;
	do {
		if(next.rdata.front().name == loop_check) {
			wout() << "Encountered CNAME loop for " << cname;
			return rrset_rdata<RDATA>(RDATA::get_type(), dns_class_t::IN, ttlexp());
		}
		last = next;
		next = get_rrset<cname_rdata>(next.rdata.front().name);
		if(++count & 1)
			loop_check = get_rrset<cname_rdata>(loop_check).rdata.front().name;
	} while(next.record_count() > 0);
	return get_rrset<RDATA>(last.rdata.back().name);
}




#endif // CACHE_H
