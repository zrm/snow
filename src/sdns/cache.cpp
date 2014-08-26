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

#include "cache.h"
#include "configuration.h"
#include <fstream>
#include <algorithm>
#include <exception>


const size_t dcache::MAXKEYLEN(UINT8_MAX);
const size_t dcache::MAXDATALEN(UINT16_MAX);
const size_t dcache::HDRLEN(16); // 4-byte link; 1-byte rrset type; 1-byte key len; 2-byte rrset len; 8-byte expire time

dcache::dcache()
{
	size = sdns::conf[sdns::CACHE_SIZE];
	
	hsize = 4;
	while (hsize <= (size >> 5)) hsize <<= 1;
	
	cache = new uint8_t[size];
	memset(cache, 0, size);
	
	writer = hsize;
	oldest = size;
	unused = size;
}

unsigned int dcache::hash(const uint8_t *key, unsigned int keylen) const
{
	unsigned int result = 5381;
	
	while (keylen) {
		result = (result << 5) + result;
		result ^= *key;
		++key;
		--keylen;
	}
	result <<= 2;
	result &= hsize - 4;
	return result;
}

dcache::cache_entry dcache::cache_get(const uint8_t *key, unsigned int keylen, dns_type_t tp, size_t *datalen, uint64_t *ttl) const
{
	uint64_t expire;
	uint64_t now;
	uint32_t pos;
	uint32_t prevpos;
	uint32_t nextpos;
	uint32_t u;
	unsigned int loop;
	
	if (!cache) return nullptr;
	if (keylen > MAXKEYLEN) return nullptr;
	if (tp > UINT8_MAX) return nullptr;
	
	prevpos = hash(key,keylen);
	pos = get<uint32_t>(prevpos);
	loop = 0;
	
	now = ttlexp::now();
	while(pos) {
		if(cache[pos+5] == keylen) {
			if(pos + HDRLEN + keylen > size) cache_impossible();
			cache_entry entry(cache+pos);
			dns_type_t rtype = entry.get_type();
			if(rtype == tp && memcmp(key, cache + pos + HDRLEN, keylen) == 0) {
				expire = entry.get_expiration();
				if(expire < now) return nullptr;
				if(expire - now > sdns::conf[sdns::MAX_TTL])
					expire = now + sdns::conf[sdns::MAX_TTL];
				*ttl = expire;
				
				u = entry.get_datalen();
				if (u > size - pos - HDRLEN - keylen) cache_impossible();
				*datalen = u;
				
				return entry;
			}
		}
		nextpos = prevpos ^ get<uint32_t>(pos);
		prevpos = pos;
		pos = nextpos;
		if (++loop > 100) return nullptr; /* to protect against hash flooding */
	}
	return nullptr;
}

void dcache::cache_set(const uint8_t *key, unsigned int keylen, const rrset_data & rrset)
{
	uint64_t expire;
	unsigned int entrylen;
	unsigned int keyhash;
	uint32_t pos;
	size_t datalen = rrset.cache_size();
	uint32_t ttl;
	
	if (!cache) return;
	if (keylen > MAXKEYLEN) return;
	if (datalen > MAXDATALEN) return;
	if (rrset.get_type() > UINT8_MAX) return;
	
	ttl = rrset.expire.rel();
	if (!ttl) return;
	if (ttl > sdns::conf[sdns::MAX_TTL]) expire = ttlexp::abs(sdns::conf[sdns::MAX_TTL]);
	else expire = rrset.expire.ttl;
	
	entrylen = HDRLEN + keylen + datalen;
	
	while (writer + entrylen > oldest) {
		if (oldest == unused) {
			if (writer <= hsize) return;
			unused = writer;
			oldest = hsize;
			writer = hsize;
		}
		
		pos = get<uint32_t>(oldest); // get pos of second-to-last list element
		set<uint32_t>(pos, get<uint32_t>(pos) ^ oldest); // second-to-last element is now last element, do not follow chain to deleted "oldest"
		
		cache_entry oldest_entry(cache + oldest);
		oldest += HDRLEN + oldest_entry.get_keylen() + oldest_entry.get_datalen(); // discard "oldest" record
		if (oldest > unused) cache_impossible();
		if (oldest == unused) {
			unused = size;
			oldest = size;
		}
	}
	
	keyhash = hash(key, keylen);
	
	pos = get<uint32_t>(keyhash);
	if(pos)
		set<uint32_t>(pos, get<uint32_t>(pos) ^ keyhash ^ writer);
	set<uint32_t>(writer, pos ^ keyhash);
	cache[writer + 4] = rrset.get_type();
	cache[writer + 5] = keylen;
	set<uint16_t>(writer + 6, datalen);
	set<uint64_t>(writer + 8, expire);
	memcpy(cache + writer + HDRLEN, key, keylen);
	rrset.cache_write_rrset(cache + writer + HDRLEN + keylen);
	
	set<uint32_t>(keyhash,writer);
	writer += entrylen;
//	cache_motion += entrylen;
}


void dcache::copy_entry(const uint8_t * data, size_t datalen, rrset_data & rrset)
{
	try {
		while(datalen)
			rrset.add_record(&data, &datalen);
	} catch(const e_invalid_input &e) {
		eout() << "BUG: Invalid data in cache: " << e << ", program terminated";
		abort();
	}
}

bool dcache::contains_record(const domain_name &name, dns_type_t tp) const
{
	size_t datalen;
	uint64_t ttl; //
	return cache_get(name.cache_get(), name.cache_size(), tp, &datalen, &ttl).entry_exists() && datalen > 0;
}

std::unique_ptr<rrset_data> dcache::get_rrset(const domain_name & name, dns_type_t tp) const
{
	// safety note: checking is_cacheable also ensures that records of type 255 (used for NODATA/NXDOMAIN SOA) are never returned from here, which would otherwise abort program
	// since those records stored in cache are not stored in the default_rdata format that the rrset_data given by get_rrset_data() would attempt to parse it in
	if(tp.is_cachable() == false) return nullptr;
	size_t datalen;
	ttlexp expire;
	cache_entry entry = cache_get(name.cache_get(), name.cache_size(), tp, &datalen, &expire.ttl);
	if(!entry.entry_exists()) return nullptr;
	std::unique_ptr<rrset_data> rrset(rrset_data::get_rrset_data(entry.get_type(), dns_class_t::IN, expire));
	copy_entry(entry.get_data(), datalen, *rrset);
	return std::move(rrset);
}


// ncache_rdata is a pseudo-rdata type which contains an SOA record required for either NXDOMAIN or NODATA, and specifies which one
struct ncache_rdata
{
	const domain_name * name;
	const soa_rdata * soa;
	bool nxdomain; // NXDOMAIN vs. NODATA
	enum { NCACHE_TYPE = 255 }; // equivalent to qtype ANY which is otherwise never used in cache
	static unsigned get_type() { return NCACHE_TYPE; }
	size_t cache_size() const { return name->cache_size() + soa->cache_size() + 1; }
	uint8_t * cache_write(uint8_t * data) const {
		data = name->cache_write(data);
		data = soa->cache_write(data);
		*data = nxdomain ? 1 : 0;
		return data+1;
	}
	void print(std::ostream &out) const { out << name << " "; soa->print(out); out << " nxdomain: " << nxdomain; }
	ncache_rdata(const domain_name * n, const soa_rdata * s, bool nx) : name(n), soa(s), nxdomain(nx) {}
	bool operator==(const ncache_rdata & nr) const { return *name == *nr.name && *soa == *nr.soa && nxdomain == nr.nxdomain; }
	bool operator!=(const ncache_rdata & nr) const { return !(*this == nr); }
	// the template requires these functions to exist but they should never be used for pseudo-rdata:
	size_t maxsize() const { abort(); return 0; }
	size_t write(uint8_t*,size_t,dns_compression_node&) const { abort(); return 0; }
	ncache_rdata(const dns_raw_msg&, size_t&) { abort(); }
	ncache_rdata(const uint8_t**, size_t*) { abort(); }
};

void dcache::ncache_nodata(const domain_name & name, dns_type_t tp, const domain_name & soa_name, const rrset_rdata<soa_rdata> & soa)
{
	if(tp.is_cachable() == false || soa.record_count() != 1) return;
	std::unique_ptr<rrset_data> rr(rrset_data::get_rrset_data(tp, dns_class_t::IN, ttlexp(soa.rdata.front().minimum)));
	if(rr->expire.ttl > soa.expire.ttl) rr->expire = soa.expire; // no use caching NODATA entry for longer than SOA TTL
	cache_set(name.cache_get(), name.cache_size(), *rr);
	ncache_nx(name, soa_name, soa, false);
}
void dcache::ncache_nx(const domain_name & name, const domain_name & soa_name, const rrset_rdata<soa_rdata> & soa, bool nxdomain)
{
	if(soa.record_count() != 1) return;
	ttlexp expire(soa.rdata.front().minimum);
	if(expire.ttl > soa.expire.ttl) expire = soa.expire;
	rrset_rdata<ncache_rdata> ncache(ncache_rdata::get_type(), dns_class_t::IN, expire);
	ncache.rdata.emplace_back(&soa_name, &soa.rdata.front(), nxdomain);
	dout() << "ncache_nx " << name << " soa " << soa_name;
	cache_set(name.cache_get(), name.cache_size(), ncache);
}

ncache_soa dcache::get_ncache_soa(const domain_name & name)
{
	size_t datalen;
	ttlexp expire;
	cache_entry entry = cache_get(name.cache_get(), name.cache_size(), ncache_rdata::get_type(), &datalen, &expire.ttl);
	if(entry.entry_exists()) {
		const uint8_t * data = entry.get_data();
		try {
			domain_name soaname(&data, &datalen);
			soa_rdata soa(&data, &datalen);
			if(datalen != 1) cache_impossible();
			dout() << "Found ncache SOA entry for " << name << ": " << soaname;
			return ncache_soa(std::move(soaname), std::move(soa), expire, data[0]);
		} catch(const e_invalid_input &e) {
			eout() << "BUG: Invalid data in ncache: " << e << ", program terminated";
			abort();
		}
	}
	dout() << "no ncache SOA entry found for " << name;
	return ncache_soa();
}

void pcache::cache_rrset(const domain_name &name, const rrset_data& rrset)
{
	dout() << "pcache::cache_rrset " << name << " " << rrset;
	auto p = cache.emplace(name, pcache_records());
	if(!p.second) {
		for(pcache_rrset& records : p.first->second.rrsets) {
			if(records.rr->get_type() == rrset.get_type() && records.rr->get_class() == rrset.get_class()) {
				records.rr->append(rrset);
				return;
			}
		}
	}
	p.first->second.rrsets.emplace_back(rrset);
}
const rrset_data & pcache::get_rrset(const domain_name &name, dns_type_t tp, dns_class_t cl) const
{
	auto it = cache.find(name);
	if(it != cache.end())
		for(const pcache_rrset& records : it->second.rrsets)
			if(records.rr->get_type() == tp && records.rr->get_class() == cl)
				return *records.rr;
	return dns_rrset::empty_rrset;
}

void pcache::read_record_file(const std::string & filename)
{
	// sdns record file format:
	// anything on a line after ';' or '#' are comments
	// other lines begin with either a record type (A, AAAA, CNAME, NS) or a control parameter (TTL)
	// record lines have the format: [record type] [domain name] [record(s)]
	// e.g.:
	// A foo.com 10.0.0.3 192.168.5.5
	// NS . A.ROOT-SERVERS.NET.
	// A A.ROOT-SERVERS.NET. 198.41.0.4
	// AAAA A.ROOT-SERVERS.NET. 2001:503:BA3E::2:30
	// CNAME foo.bar.com www.foo.com
	// CNAME snow.baz.net quix.key
	// control parameters set their values for each subsequent record, e.g. this makes the TTL of every subsequent record 1800 until the next TTL line:
	// TTL 1800
	
	std::ifstream file(filename.c_str());
	ttlexp absttl;
	absttl.ttl = sdns::conf[sdns::DEFAULT_STATIC_TTL];
	std::string line;
	size_t linenum=0;
	std::unordered_map<std::string, dns_type_t> type_map;
	type_map["a"] = dns_type_t::A;
	type_map["aaaa"] = dns_type_t::AAAA;
	type_map["ns"] = dns_type_t::NS;
	type_map["cname"] = dns_type_t::CNAME;
	type_map["ptr"] = dns_type_t::PTR;
	while(getline(file, line)) {
		++linenum;
		size_t pos = line.find_first_of(";#");
		if(pos != std::string::npos) line.erase(pos);
		pos=0;
		std::string rtype = next_word(line, &pos);
		if(rtype.size()==0) continue; // ignore blank lines
		std::transform(rtype.begin(), rtype.end(), rtype.begin(), ::tolower);
		auto typeit = type_map.find(rtype);
		if(typeit != type_map.end()) {
			std::string rname = next_word(line, &pos);
			try {
				switch(typeit->second) {
				case dns_type_t::A:
					cache_rrset(rname, rrset_rdata<a_rdata>(line.substr(pos), absttl));
					break;
				case dns_type_t::AAAA:
					cache_rrset(rname, rrset_rdata<aaaa_rdata>(line.substr(pos), absttl));
					break;
				case dns_type_t::NS:
					cache_rrset(rname, rrset_rdata<ns_rdata>(line.substr(pos), absttl));
					break;
				case dns_type_t::CNAME:
					cache_rrset(rname, rrset_rdata<cname_rdata>(line.substr(pos), absttl));
					break;
				case dns_type_t::PTR:
					cache_rrset(rname, rrset_rdata<ptr_rdata>(line.substr(pos), absttl));
					break;
				}
			} catch(const e_invalid_input &e) {
				eout() << "Error in record file " << filename << " line " << linenum << ": " << e;
				abort();
			}
		} else if(rtype=="ttl") {
			std::string ttlstr = next_word(line, &pos);
			try {
				if(pos != line.size()) throw std::invalid_argument("data after integer");
				unsigned long ttl = stoul(ttlstr, &pos);
				if(pos != ttlstr.size()) throw std::invalid_argument("data after integer");
				if(ttl > sdns::conf[sdns::MAX_TTL]) ttl = sdns::conf[sdns::MAX_TTL];
				absttl.ttl = ttl;
			} catch(const std::exception &e) {
				eout() << "Error in record file " << filename << " line " << linenum << ": not a valid TTL: " << e.what();
				abort();
			}
		} else {
			eout() << "Error in record file " << filename << " line " << linenum << ": do not understand \"" << line << '\"';
			abort();
		}
	}
}

dns_cache::closest_ns dns_cache::get_closest_ns(const domain_name &name, int use_ip_family) const {
	// find the name servers closest to the target name that can be resolved to an address without making any queries
	dns_type_t ip_types[2];
	unsigned num_ip_types = 0;
	if(use_ip_family & IP_FAMILY::IPV4)
		ip_types[num_ip_types++] = dns_type_t::A;
	if(use_ip_family & IP_FAMILY::IPV6)
		ip_types[num_ip_types++] = dns_type_t::AAAA;
	unsigned depth = name.num_labels();
	while(depth) {
		const domain_name & ns_name = name.get_root(depth).name;
		const rrset_data &ns = static_cache.get_rrset(ns_name, dns_type_t::NS, dns_class_t::IN);
		if(ns.get_type() == dns_type_t::NS) {
			for(const ns_rdata &rdata : ns.get<ns_rdata>()) {
				if(ns_has_address(rdata, ip_types, num_ip_types)) {
					dout() << "Closest NS for " << name << " is pcache " << ns.get<ns_rdata>();
					return closest_ns(ns.get<ns_rdata>().rdata, depth);
				}
			}
		}
		rrset_rdata<ns_rdata> rrset = dynamic_cache.get_rrset<ns_rdata>(ns_name);
		if(rrset.record_count() > 0) {
			for(const ns_rdata &rdata : rrset) {
				if(ns_has_address(rdata, ip_types, num_ip_types)) {
					dout() << "Closest NS for " << name << " is dcache " << rrset;
					return closest_ns(std::move(rrset.rdata), depth);
				}
			}
		}
		--depth;
	}
	// NS fail, give root servers
	const rrset_data & ns = static_cache.get_rrset(domain_name::root, dns_type_t::NS, dns_class_t::IN);
	if(ns.get_type() != dns_type_t::NS) {
		eout() << "No root servers available";
		return closest_ns(std::vector<ns_rdata>(), 0);
	}
	dout() << "Closest NS for " << name << " is root " << ns;
	return closest_ns(ns.get<ns_rdata>().rdata, 0);
}

bool dns_cache::ns_has_address(const ns_rdata &ns, dns_type_t ip_types[], size_t num_ip_types) const
{
	for(size_t i=0; i < num_ip_types; ++i) {
		if(dynamic_cache.contains_record(ns.name, ip_types[i])) return true;
		if(static_cache.contains_record(ns.name, ip_types[i])) return true;
	}
	return false;
}

bool dns_cache::ns_in_bailiwick(const domain_name &name, const sockaddrunion &fromaddr)
{
	for(unsigned depth = name.num_labels(); depth; --depth) {
		const domain_name & ns_name = name.get_root(depth).name;
		const rrset_data &ns = static_cache.get_rrset(ns_name, dns_type_t::NS, dns_class_t::IN);
		if(ns.get_type() == dns_type_t::NS) {
			for(const ns_rdata &rdata : ns.get<ns_rdata>())
				if(ns_addr_match(rdata, fromaddr))
					return true;
			continue;
		}
		rrset_rdata<ns_rdata> rrset = dynamic_cache.get_rrset<ns_rdata>(ns_name);
		if(rrset.record_count() > 0) 
			for(const ns_rdata &rdata : rrset)
				if(ns_addr_match(rdata, fromaddr))
					return true;
	}
	// check root servers
	const rrset_data & ns = static_cache.get_rrset(domain_name::root, dns_type_t::NS, dns_class_t::IN);
	if(ns.get_type() == dns_type_t::NS) 
		for(const ns_rdata &rdata : ns.get<ns_rdata>())
			if(ns_addr_match(rdata, fromaddr))
				return true;
	return false;
}
bool dns_cache::ns_addr_match(const ns_rdata &ns, const sockaddrunion &fromaddr)
{
	if(fromaddr.s.sa_family == AF_INET) return ns_addr_match_rdata<a_rdata>(ns, fromaddr);
	if(fromaddr.s.sa_family == AF_INET6) return ns_addr_match_rdata<aaaa_rdata>(ns, fromaddr);
	return false;
}
template<class IP_RDATA>
bool dns_cache::ns_addr_match_rdata(const ns_rdata &ns, const sockaddrunion &fromaddr)
{
	const rrset_data & ns_addr = static_cache.get_rrset(ns.name, IP_RDATA::get_type(), dns_class_t::IN);
	if(ns_addr.get_type() == IP_RDATA::get_type()) {
		for(const IP_RDATA & rdata : ns_addr.get<IP_RDATA>())
			if(rdata == fromaddr)
				return true;
		return false;
	}
	rrset_rdata<IP_RDATA> addr = dynamic_cache.get_rrset<IP_RDATA>(ns.name);
	for(const IP_RDATA & rdata : addr)
		if(rdata == fromaddr)
			return true;
	return false;
}
std::unique_ptr<rrset_data> dns_cache::get_rrset(const domain_name &name, dns_type_t tp, dns_class_t cl) const
{
	if(cl != dns_class_t::IN || tp.is_cachable() == false) return nullptr;
	const rrset_data &r = static_cache.get_rrset(name, tp, cl);
	if(r.get_type() == tp && r.record_count() > 0) {
		std::unique_ptr<rrset_data> rr(r.clone());
		rr->expire.ttl += ttlexp::now();
		return std::move(rr);
	}
	return dynamic_cache.get_rrset(name, tp);
}

std::vector< dns_record<cname_rdata> > dns_cache::follow_cname(domain_name target_name, rrset_rdata<cname_rdata> cname) const /*throw(cname_loop_exception)*/ {
	std::vector< dns_record<cname_rdata> > cname_chain;
	size_t loop_check = 0;
	while(cname.get_type() == dns_type_t::CNAME && cname.record_count() == 1) {
		cname_chain.emplace_back(target_name, dns_type_t::CNAME, cname.get_class(), cname.expire, std::move(cname.rdata.front()));
		target_name = cname_chain.back().rdata.name;
		cname = get_rrset<cname_rdata>(target_name);
		if(target_name == cname_chain[loop_check].name)
			throw cname_loop_exception();
		if((cname_chain.size() & 1) == 0)
			++loop_check;
	}
	return std::move(cname_chain);
}


void dns_cache::cache_rrset(const domain_name & name, const rrset_data * rrset, bool force)
{
	if(!rrset) return;
	if(!force && dynamic_cache.contains_record(name, rrset->get_type())) return;
	dynamic_cache.cache_rrset(name, *rrset);
}

void dns_cache::cache_rrset_static(const domain_name & name, const rrset_data * rrset)
{
	if(!rrset) return;
	static_cache.cache_rrset(name, *rrset);
}

bool dns_cache::contains_record(const domain_name & name, dns_type_t tp, dns_class_t cl)
{
	if(cl != dns_class_t::IN) return false;
	if(static_cache.contains_record(name, tp, cl)) return true;
	return dynamic_cache.contains_record(name, tp);
}



