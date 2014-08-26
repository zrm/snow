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

#ifndef DNS_RECORD_H
#define DNS_RECORD_H
#include<cstdint>
#include<cstring>
#include<algorithm>
#include"../common/network.h"
#include"../common/dbuf.h"
#include"../common/byte_order.h"
#include"configuration.h"
#include"dns_field.h"
#include"domain_name.h"
using std::size_t;



template<class UINT> inline UINT read_nbo_cache(const uint8_t ** data, size_t * len) {
	if(*len < sizeof(UINT)) throw e_invalid_input("read truncated data from cache");
	UINT rv;
	memcpy(&rv, *data, sizeof(rv));
	*data += sizeof(UINT);
	*len -= sizeof(UINT);
	return rv;
}

template<class UINT> inline UINT read_nbo_dnsmsg(dns_raw_msg dnsmsg, size_t * offset) {
	if(dnsmsg.len < *offset + sizeof(UINT)) throw e_invalid_input("read truncated data from DNS message");
	UINT rv;
	memcpy(&rv, dnsmsg.msg + *offset, sizeof(rv));
	*offset += sizeof(UINT);
	return rv;
}


/*
[x]_rdata must implement the following functions:
	[x]_rdata(dns_raw_msg dnsmsg, size_t offset)
		DNS message constructor, read rdata from DNS message starting at offset
		must pass entire DNS message because of DNS label compression
		dnsmsg.len should indicate end of rdata rather than end of dnsmsg
	[x]_rdata(const uint8_t ** data, size_t * len)
		cache constructor, reads bytes from *data (up to *len), advances data and reduces len
		this may or may not be the same as the DNS message wire format for a given rdata type
	void print(std::ostream &out) const
		output rdata to ostream
	size_t maxsize() const
		the maximum size this rdata will require in a DNS message (assuming no label compression)
	size_t write(uint8_t *msg, size_t msg_offset, dns_compression_node &dcn) const
		write rdata (up to maxsize()) to msg starting at msg_offset, use dcn to compress domain names if rdata type was listed in RFC1035
		return how many bytes were written
	size_t cache_size() const
		number of bytes that will be written by cache_write
	uint8_t * cache_write(uint8_t *data) const
		write exactly cache_size() bytes to data in cache format (may differ from DNS message format), returns ptr to data after bytes written
		data written by cache_write() when passed to cache constructor should reconstruct the original object
a specific rdata type may optionally implement:
	static dns_type_t get_type() const
		get_type is not required and should not be implemented unless it can statically return the correct record type
		its primary purpose is to provide the record type when an rdata struct is used as a template argument
	static [x]_rdata get_rdata(const std::string & s)
		convert string to rdata object
*/

// domain_name_rdata is used for most rdata types for which the data is solely a single domain name
	// however, non-RFC1035 types if they subclass this must override write() to not use label compression, as follows:
	// size_t write(uint8_t *msg, size_t msg_offset, dns_compression_node &) const { name.write(msg, msg_offset); }
struct domain_name_rdata
{
	domain_name name;
	domain_name_rdata(dns_raw_msg dnsmsg, size_t offset) : name(dnsmsg, &offset) {}
	domain_name_rdata(const uint8_t ** data, size_t * len) : name(data, len) {}
	domain_name_rdata(const domain_name &nm) : name(nm) {}
	void print(std::ostream &out) const {
		out << name;
	}
	size_t maxsize() const { return name.maxsize(); }
	size_t write(uint8_t *msg, size_t msg_offset, dns_compression_node &dcn) const {
		return name.write(msg, msg_offset, dcn);
	}
	size_t write(uint8_t *msg, size_t msg_offset) const {
		return name.write(msg, msg_offset);
	}
	size_t cache_size() const { return name.cache_size(); }
	uint8_t * cache_write(uint8_t* data) const { return name.cache_write(data); }
	bool operator==(const domain_name_rdata & dn) const { return name == dn.name; }
	bool operator!=(const domain_name_rdata & dn) const { return name != dn.name; }
};
struct ns_rdata : public domain_name_rdata {
	ns_rdata(dns_raw_msg dnsmsg, size_t offset) : domain_name_rdata(dnsmsg, offset) {}
	ns_rdata(const uint8_t ** data, size_t * len) : domain_name_rdata(data, len) {}
	ns_rdata(const domain_name &nm) : domain_name_rdata(nm) {}
	static dns_type_t get_type() { return dns_type_t::NS; }
	static ns_rdata get_rdata(const std::string & s) { return ns_rdata(domain_name(s)); }
};
struct cname_rdata : public domain_name_rdata {
	cname_rdata(dns_raw_msg dnsmsg, size_t offset) : domain_name_rdata(dnsmsg, offset) {}
	cname_rdata(const uint8_t ** data, size_t* len) : domain_name_rdata(data, len) {}
	cname_rdata(const domain_name &nm) : domain_name_rdata(nm) {}
	static dns_type_t get_type() { return dns_type_t::CNAME; }
	static cname_rdata get_rdata(const std::string & s) { return cname_rdata(domain_name(s)); }
};
struct ptr_rdata : public domain_name_rdata {
	ptr_rdata(dns_raw_msg dnsmsg, size_t offset) : domain_name_rdata(dnsmsg, offset) {}
	ptr_rdata(const uint8_t ** data, size_t * len) : domain_name_rdata(data, len) {}
	ptr_rdata(const domain_name &nm) : domain_name_rdata(nm) {}
	static dns_type_t get_type() { return dns_type_t::PTR; }
	static ptr_rdata get_rdata(const std::string & s) { return ptr_rdata(domain_name(s)); }
};

struct minfo_rdata
{
	domain_name rmailbx;
	domain_name emailbx;
	minfo_rdata(const uint8_t ** data, size_t * len) : rmailbx(data, len), emailbx(data, len) {}
	minfo_rdata(dns_raw_msg dnsmsg, size_t offset) : rmailbx(dnsmsg, &offset), emailbx(dnsmsg, &offset) {}
	void print(std::ostream &out) const { out << "rmailbx: " << rmailbx << " emailbx: " << emailbx; }
	size_t maxsize() const { return rmailbx.maxsize() + emailbx.maxsize(); }
	size_t write(uint8_t *msg, size_t msg_offset, dns_compression_node &dcn) const {
		msg_offset = rmailbx.write(msg, msg_offset, dcn);
		return emailbx.write(msg, msg_offset, dcn);
	}
	size_t cache_size() const { return rmailbx.cache_size() + emailbx.cache_size(); }
	uint8_t * cache_write(uint8_t * data) const {
		data = rmailbx.cache_write(data);
		return emailbx.cache_write(data);
	}
	static dns_type_t get_type() { return dns_type_t::MINFO; }
	bool operator==(const minfo_rdata & m) const { return rmailbx == m.rmailbx && emailbx == m.emailbx; }
	bool operator!=(const minfo_rdata & m) const { return !(*this == m); }
};
struct mx_rdata
{
	uint16_t preference; // NBO
	domain_name exchange;
	mx_rdata(const uint8_t ** data, size_t * len) : preference(read_nbo_cache<uint16_t>(data, len)), exchange(data, len) {}
	mx_rdata(dns_raw_msg dnsmsg, size_t offset) : preference(read_nbo_dnsmsg<uint16_t>(dnsmsg, &offset)), exchange(dnsmsg, &offset) {}
	void print(std::ostream &out) const { out << "preference: " << ntohs(preference) << " exchange: " << exchange; }
	size_t maxsize() const { return sizeof(preference) + exchange.maxsize(); }
	size_t write(uint8_t *msg, size_t msg_offset, dns_compression_node &dcn) const {
		write_nbo<uint16_t>(preference, msg + msg_offset);
		return exchange.write(msg, msg_offset + sizeof(preference), dcn);
	}
	size_t cache_size() const { return 2/*preference*/ + exchange.cache_size(); }
	uint8_t * cache_write(uint8_t * data) const {
		write_nbo<uint16_t>(preference, data);
		return exchange.cache_write(data+sizeof(preference));
	}
	static dns_type_t get_type() { return dns_type_t::MX; }
	bool operator==(const mx_rdata & m) const { return preference == m.preference && exchange == m.exchange; }
	bool operator!=(const mx_rdata & m) const { return (*this == m); }
};

struct soa_rdata
{
	domain_name mname;
	domain_name rname;
	// these are all host byte order:
	uint32_t serial;
	uint32_t refresh;
	uint32_t retry;
	uint32_t expire;
	uint32_t minimum;
	soa_rdata(const uint8_t ** data, size_t * len) : mname(data, len), rname(data, len) {
		read_fields(*data, *len);
		*data += 5*sizeof(uint32_t);
		*len -= 5*sizeof(uint32_t);
	}
	soa_rdata(dns_raw_msg dnsmsg, size_t offset) : mname(dnsmsg, &offset), rname(dnsmsg, &offset) { read_fields(dnsmsg.msg + offset, dnsmsg.len - offset); }
	soa_rdata(domain_name mnam, domain_name rnam, uint32_t ser, uint32_t ref, uint32_t ret, uint32_t exp, uint32_t min)
		: mname(std::move(mnam)), rname(std::move(rnam)), serial(ser), refresh(ref), retry(ret), expire(exp), minimum(min) {}
	void read_fields(const uint8_t * data, size_t len);
	void write_fields(uint8_t * data) const;
	
	void print(std::ostream &out) const {
		out << "mname: " << mname << " rname: " << rname << " serial: " << serial << " refresh: " << refresh
			<< " retry: " << retry << " expire: " << expire << " minimum: " << minimum;
	}
	size_t maxsize() const { return mname.maxsize() + rname.maxsize() + 5*sizeof(uint32_t); }
	size_t write(uint8_t *msg, size_t msg_offset, dns_compression_node &dcn) const {
		msg_offset = mname.write(msg, msg_offset, dcn);
		msg_offset = rname.write(msg, msg_offset, dcn);
		write_fields(msg + msg_offset);
		return msg_offset + 5*sizeof(uint32_t);
	}
	size_t cache_size() const { return mname.cache_size() + rname.cache_size() + 5*sizeof(uint32_t); }
	uint8_t * cache_write(uint8_t * data) const {
		data = mname.cache_write(data);
		data = rname.cache_write(data);
		write_fields(data);
		return data + 5*sizeof(uint32_t);
	}
	static dns_type_t get_type() { return dns_type_t::SOA; }
	bool operator==(const soa_rdata & s) const
		{ return mname == s.mname && rname == s.rname && serial == s.serial && refresh == s.refresh && retry == s.retry && expire == s.expire && minimum == s.minimum; }
	bool operator!=(const soa_rdata & s) const { return !(*this == s); }
};

struct a_rdata
{
	uint32_t address; // network byte order
	a_rdata(const uint8_t ** data, size_t * len) {
		if(*len < sizeof(address))
			throw e_invalid_input("truncated A record rdata");
		address = read_nbo<uint32_t>(*data);
		*data +=  sizeof(address);
		*len -=  sizeof(address);
	}
	a_rdata(dns_raw_msg dnsmsg, size_t offset) {
		if(dnsmsg.len < offset +  sizeof(address))
			throw e_invalid_input("truncated A record rdata");
		address = read_nbo<uint32_t>(dnsmsg.msg + offset);
	}
	a_rdata(uint32_t addr) : address(addr) {}
	void print(std::ostream &out) const { out << ss_ipaddr(address); }
	a_rdata(const std::string & addrstr) {
		if(inet_pton(AF_INET, addrstr.c_str(), &address) != 1)
			throw e_invalid_input("invalid address string constructing A record rdata");
	}
	size_t maxsize() const { return sizeof(address); }
	size_t write(uint8_t *msg, size_t msg_offset, dns_compression_node &) const {
		write_nbo<uint32_t>(address, msg+msg_offset);
		return msg_offset + sizeof(address);
	}
	size_t cache_size() const { return sizeof(address); }
	uint8_t * cache_write(uint8_t * data) const { write_nbo<uint32_t>(address, data); return data + sizeof(address); }
	static dns_type_t get_type() { return dns_type_t::A; }
	static a_rdata get_rdata(const std::string & addrstr) {
		a_rdata rv(0U);
		if(inet_pton(AF_INET, addrstr.c_str(), &rv.address) != 1)
			throw e_invalid_input(std::string("A record string failed to parse as IPv4 address: ") + addrstr);
		return rv;
	}
	bool operator==(const a_rdata & a) const { return address == a.address; }
	bool operator==(const sockaddrunion & su) const { return su.sa.sin_family == AF_INET && su.sa.sin_addr.s_addr == address; }
	template<class T> bool operator!=(const T & t) const { return !(*this == t); }
};

struct aaaa_rdata
{
	uint8_t address[16];
	aaaa_rdata(const uint8_t ** data, size_t * len) {
		if(*len < sizeof(address))
			throw e_invalid_input("truncated AAAA record rdata");
		memcpy(address, *data, sizeof(address));
		*data += sizeof(address);
		*len -= sizeof(address);
	}
	aaaa_rdata(dns_raw_msg dnsmsg, size_t offset) {
		if(dnsmsg.len < offset + sizeof(address))
			throw e_invalid_input("truncated AAAA record rdata");
		memcpy(address, dnsmsg.msg+offset, sizeof(address));
	}
	aaaa_rdata(const std::string & addrstr) {
		if(inet_pton(AF_INET6, addrstr.c_str(), address) != 1)
			throw e_invalid_input("invalid address string constructing AAAA record rdata");
	}
	void print(std::ostream &out) const {
		char str[INET6_ADDRSTRLEN] = {0};
		inet_ntop(AF_INET6, address, str, INET6_ADDRSTRLEN);
		out << "IPv6 addr:" << str;
	}
	size_t maxsize() const { return sizeof(address); }
	size_t write(uint8_t *msg, size_t msg_offset, dns_compression_node &) const {
		memcpy(msg+msg_offset, address, sizeof(address));
		return msg_offset + sizeof(address);
	}
	size_t cache_size() const { return sizeof(address); }
	uint8_t * cache_write(uint8_t * data) const { memcpy(data, &address, sizeof(address)); return data + sizeof(address); }
	static dns_type_t get_type() { return dns_type_t::AAAA; }
	static aaaa_rdata get_rdata(const std::string & addrstr) {
		aaaa_rdata rv;
		if(inet_pton(AF_INET6, addrstr.c_str(), &rv.address) != 1)
			throw e_invalid_input(std::string("AAAA record string failed to parse as IPv6 address: ") + addrstr);
		return rv;
	}
	bool operator==(const aaaa_rdata & a) const { return memcmp(address, a.address, sizeof(address)) == 0; }
	bool operator==(const sockaddrunion & su) const { return su.sa6.sin6_family == AF_INET6 && memcmp(su.sa6.sin6_addr.s6_addr, address, sizeof(address)) == 0; }
	template<class T> bool operator!=(const T & t) const { return !(*this == t); }
private: 
	aaaa_rdata() {} // for get_rdata()
};


// default: anything not needing special treatment and not listed in RFC1035 (so no DNS compression), just store as raw data
struct default_rdata
{
	dbuf rdata;
	default_rdata(const uint8_t ** data, size_t * len) {
		// default_rdata contains size header as the data is opaque and its length cannot be determined otherwise
		uint16_t size;
		if(*len < sizeof(size)) throw e_invalid_input("truncated default_rdata lenth from cache");
		memcpy(&size, *data, sizeof(size));
		if(*len < size + sizeof(size)) throw e_invalid_input("truncated default_rdata from cache");
		rdata.resize(size);
		memcpy(rdata, (*data)+sizeof(size), size);
		*data += size + sizeof(size);
		*len -= size + sizeof(size);
	}
	default_rdata(dns_raw_msg dnsmsg, size_t offset) : rdata(dnsmsg.len - offset) {
		if(rdata.size() > UINT16_MAX) { eout() << "BUG: default_rdata in excess of maximum message length"; abort(); }
		memcpy(rdata, dnsmsg.msg + offset, rdata.size());
	}
	void print(std::ostream &out) const {
		out << "(raw rdata " << rdata.size() << " bytes)";
	}
	size_t maxsize() const { return rdata.size(); }
	size_t write(uint8_t *msg, size_t msg_offset, dns_compression_node &) const {
		memcpy(msg+msg_offset, rdata, rdata.size());
		return msg_offset + rdata.size();
	}
	size_t cache_size() const { return 2 + rdata.size(); }
	uint8_t * cache_write(uint8_t * data) const {
		uint16_t len = rdata.size();
		memcpy(data, &len, sizeof(len));
		memcpy(data+sizeof(len), rdata, len);
		return data + sizeof(len) + len;
	}
	bool operator==(const default_rdata & d) const { return rdata.size() == d.rdata.size() && memcmp(rdata, d.rdata, rdata.size()) == 0; }
	bool operator!=(const default_rdata & d) const { return !(*this == d); }
};

template<class T>
struct rdata_print
{
	const T & rdata;
	rdata_print(const T & t) : rdata(t) {}
};
template<class T>
rdata_print<T> print_rdata(const T & rdata) { return rdata_print<T>(rdata); }
template<class T>
std::ostream& operator<<(std::ostream& out, const rdata_print<T> & rd)
{
	rd.rdata.print(out);
	return out;
}

struct ttlexp
{
	// TTL expiration
	// under normal circumstances this is the absolute time that the TTL expires in seconds since epoch of std::chrono::steady_clock
	// in persistent_cache it is the relative TTL and is adjusted (by adding now()) before being returned
	uint64_t ttl;
	static uint64_t now() { return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count(); }
	static uint64_t abs(uint32_t relttl) { return now() + (relttl < sdns::conf[sdns::MAX_TTL] ? relttl : sdns::conf[sdns::MAX_TTL]); }
	uint32_t rel() const {
		int64_t secs = ttl - now() - 1; // (round down)
		if(secs < 0) return 0;
		if((uint64_t)secs > sdns::conf[sdns::MAX_TTL]) return sdns::conf[sdns::MAX_TTL];
		return secs;
	}
	bool expired() const { return ttl < now(); }
	ttlexp() : ttl(0) {}
	explicit ttlexp(uint32_t relttl) : ttl(abs(relttl)) {}
};


// individual DNS record, for when there will not be more than one record per name/type/class tuple (e.g. CNAME, SOA)
template<class RDATA>
struct dns_record
{
	domain_name name;
	dns_type_t RR_type;
	dns_class_t RR_class;
	ttlexp expire;
	RDATA rdata;
	dns_record(const domain_name &nm, dns_type_t tp, dns_class_t cl, ttlexp ttl, const RDATA &element)
		: name(nm), RR_type(tp), RR_class(cl), expire(ttl), rdata(element) {}
	dns_record(const domain_name &nm, dns_type_t tp, dns_class_t cl, ttlexp ttl, RDATA &&element)
		: name(nm), RR_type(tp), RR_class(cl), expire(ttl), rdata(std::move(element)) {}
	dns_record(const dns_record& r) : name(r.name), RR_type(r.RR_type), RR_class(r.RR_class), expire(r.expire), rdata(r.rdata) {}
	dns_record(dns_record&& rr) : name(std::move(rr.name)), RR_type(rr.RR_type), RR_class(rr.RR_class), expire(rr.expire), rdata(std::move(rr.rdata)) {}
	dns_record &operator=(const dns_record& rr) {
		name = rr.name;
		RR_type = rr.RR_type;
		RR_class = rr.RR_class;
		expire = rr.expire;
		rdata = rr.rdata;
		return *this;
	}
	dns_record &operator=(dns_record&& rr) {
		name = std::move(rr.name);
		RR_type = rr.RR_type;
		RR_class = rr.RR_class;
		expire = rr.expire;
		rdata = std::move(rr.rdata);
		return *this;
	}
	dns_type_t get_type() const { return RR_type; }
	dns_class_t get_class() const { return RR_class; }
	bool operator==(const dns_record<RDATA>& dr) { return name == dr.name && RR_type == dr.RR_type && RR_class == dr.RR_class && rdata == dr.rdata; }
};

template<class RDATA> class rrset_rdata;

struct rrset_data
{
	dns_type_t RR_type;
	dns_class_t RR_class;
	ttlexp expire;
	rrset_data(dns_type_t tp, dns_class_t cl, ttlexp ttl) : RR_type(tp), RR_class(cl), expire(ttl) {}
	rrset_data(dns_type_t tp, dns_class_t cl, uint32_t ttl) : RR_type(tp), RR_class(cl), expire(ttl) {}
	dns_type_t get_type() const { return RR_type; }
	dns_class_t get_class() const { return RR_class; }
	static std::unique_ptr<rrset_data> get_rrset_data(dns_type_t tp, dns_class_t cl, ttlexp ttl);
	template<class T> rrset_rdata<T>& get() { return *static_cast<rrset_rdata<T>*>(this); }
	template<class T> const rrset_rdata<T>& get() const { return *static_cast<const rrset_rdata<T>*>(this); }
	virtual size_t maxsize(size_t namesize) const = 0;
	virtual size_t write_rrset(uint8_t *msg, size_t msg_offset, dns_compression_node &dcn, const domain_name &name) const = 0;
	virtual size_t cache_size() const = 0;
	virtual void cache_write_rrset(uint8_t *data) const = 0; // write cache_size() bytes to data
	virtual void add_record(dns_raw_msg msg, size_t offset) = 0; // record shall be parsed as RR_type from DNS message, throws e_invalid_input
	virtual void add_record(const uint8_t ** data, size_t * len) = 0; // record shall be parsed as RR_type from cache, data and len are updated, throws e_invalid_input
	virtual size_t record_count() const = 0;
	virtual void randomize_rdata_order() = 0;
	virtual void print_rdata(std::ostream &out) const = 0;
	virtual std::unique_ptr<rrset_data> clone() const = 0;
	virtual void append(const rrset_data & rrset) = 0;
	virtual ~rrset_data() {}
	virtual bool operator==(const rrset_data &) const = 0;
};

std::ostream &operator<<(std::ostream &out, const rrset_data &rr);

template<class RDATA>
struct rrset_rdata : public rrset_data
{
	std::vector<RDATA> rdata;
	rrset_rdata(dns_type_t tp, dns_class_t cl, ttlexp ttl) : rrset_data(tp, cl, ttl) { }
	rrset_rdata(dns_type_t tp, dns_class_t cl, ttlexp ttl, const RDATA &element) : rrset_data(tp, cl, ttl) { rdata.emplace_back(element); }
	rrset_rdata(const dns_record<RDATA> &r) : rrset_data(r.RR_type, r.RR_class, r.expire) { rdata.emplace_back(r.rdata); }
	rrset_rdata(dns_record<RDATA> &&r) : rrset_data(r.RR_type, r.RR_class, r.expire) { rdata.emplace_back(std::move(r.rdata)); }
	// rdata-specific string constructor, not implemented for all RDATA types (requires RDATA::get_type()/get_rdata()), throws e_invalid_input
	// string format is plaintext record list, e.g. for a_rdata "10.0.0.1 192.168.5.5"
	rrset_rdata(const std::string & s, ttlexp ttl) : rrset_data(RDATA::get_type(), dns_class_t::IN, ttl) {
		size_t pos = 0;
		while(pos < s.size()) {
			std::string recstr = next_word(s, &pos);
			rdata.emplace_back(RDATA::get_rdata(recstr));
		}
	}
	void add_rdata(RDATA &&rd) { rdata.emplace_back(std::move(rd)); }
	size_t maxsize(size_t namesize) const {
		size_t hdr_size = namesize + 2/*RR_type*/ + 2/*RR_class*/ + 4/*TTL*/;
		size_t sz = 0;
		for(const RDATA &r : rdata)
			sz += hdr_size + r.maxsize();
		return sz;
	}
	size_t write_rrset(uint8_t *msg, size_t msg_offset, dns_compression_node &dcn, const domain_name &name) const {
		uint32_t ttl = expire.rel();
		for(const RDATA &rd : rdata) {
			msg_offset = name.write(msg, msg_offset, dcn);
			write_hbo<uint16_t>(RR_type, msg + msg_offset);
			msg_offset += 2;
			write_hbo<uint16_t>(RR_class, msg + msg_offset);
			msg_offset += 2;
			write_hbo<uint32_t>(ttl, msg + msg_offset);
			msg_offset += 6; // ttl (4) + rdata length (2)
			size_t rd_end = rd.write(msg, msg_offset, dcn);
			write_hbo<uint16_t>(rd_end - msg_offset, msg + msg_offset - 2); // go back and write rdata length
			msg_offset = rd_end;
		}
		return msg_offset;
	}
	size_t cache_size() const {
		size_t sz = 0;
		for(const RDATA &r : rdata)
			sz += r.cache_size();
		return sz;
	}
	void cache_write_rrset(uint8_t * data) const {
		for(const RDATA &r : rdata)
			data = r.cache_write(data);
	}
	void add_record(dns_raw_msg msg, size_t offset) { rdata.emplace_back(msg, offset); }
	void add_record(const uint8_t ** data, size_t * len);
	size_t record_count() const { return rdata.size(); }
	void randomize_rdata_order() { std::random_shuffle(rdata.begin(), rdata.end()); }
	virtual std::unique_ptr<rrset_data> clone() const { return std::unique_ptr<rrset_data>(new rrset_rdata<RDATA>(*this)); }
	virtual void append(const rrset_data & rrset) {
		if(rrset.get_type() != get_type()) {
			eout() << "BUG: rrset_rdata::append() " << get_type() << " called with incompatible type " << rrset.get_type() << ", program terminated";
			abort();
		}
		rdata.reserve(rdata.size() + rrset.get<RDATA>().rdata.size());
		for(const RDATA & x : rrset.get<RDATA>())
			rdata.emplace_back(x);
	}
	void print_rdata(std::ostream &out) const {
		for(const RDATA &r : rdata) {
			out << " ";
			r.print(out);
		}
	}
	virtual bool operator==(const rrset_data &rr) const {
		if(get_type() != rr.get_type() || get_class() != rr.get_class()) return false;
		const rrset_rdata<RDATA> & rrd = rr.get<RDATA>();
		if(rdata.size() != rrd.rdata.size()) return false;
		for(size_t i=0; i < rrd.rdata.size(); ++i)
			if(std::find(rdata.begin(), rdata.end(), rrd.rdata[i]) == rdata.end())
				return false;
		return true;
	}
	typename std::vector<RDATA>::const_iterator begin() const { return rdata.begin(); }
	typename std::vector<RDATA>::const_iterator end() const { return rdata.end(); }
};

// add_record gets called any time any rrset is constructed from the cache, which happens a lot, so this is an optimization target:
template<>
void inline rrset_rdata<cname_rdata>::add_record(const uint8_t ** data, size_t * len)
{
	rdata.emplace_back(data, len);
}
template<>
void inline rrset_rdata<soa_rdata>::add_record(const uint8_t ** data, size_t * len)
{
	rdata.emplace_back(data, len);
}
template<class RDATA>
void inline rrset_rdata<RDATA>::add_record(const uint8_t ** data, size_t * len)
{
	if(!rdata.size()) rdata.reserve(16);
	rdata.emplace_back(data, len);
}



// dns_rrset: rrset_data with name, for cases where name is not implicit
struct dns_rrset
{
	domain_name name;
	std::unique_ptr<rrset_data> rrdata;
	dns_rrset(domain_name &&dname, dns_type_t tp, dns_class_t cl, ttlexp ttl) : name(std::move(dname)), rrdata(rrset_data::get_rrset_data(tp, cl, ttl)) {}
	dns_rrset(domain_name &&dname, std::unique_ptr<rrset_data> &&rdata) : name(std::move(dname)), rrdata(std::move(rdata)) {}
	dns_rrset(const domain_name &dname, const rrset_data &rr) : name(dname), rrdata(rr.clone()) {}
	dns_rrset(const dns_rrset& d) : name(d.name), rrdata(d.rrdata->clone()) {}
	dns_rrset(dns_rrset&&) = default;
	template<class RDATA> dns_rrset(const dns_record<RDATA> &rr) : name(rr.name), rrdata(new rrset_rdata<RDATA>(rr)) {}
	template<class RDATA> dns_rrset(dns_record<RDATA> &&rr) : name(std::move(rr.name)), rrdata(new rrset_rdata<RDATA>(std::move(rr))) {}
	size_t maxsize() const { return rrdata->maxsize(name.maxsize()); }
	size_t write(uint8_t *msg, size_t msg_offset, dns_compression_node &dcn) const { return rrdata->write_rrset(msg, msg_offset, dcn, name); }
	const domain_name& get_name() const { return name; }
	dns_type_t get_type() const { return rrdata ? rrdata->get_type() : dns_type_t::INVALID; }
	dns_class_t get_class() const { return rrdata ? rrdata->get_class() : dns_class_t::INVALID; }
	ttlexp get_ttl() const { return rrdata ? rrdata->expire : ttlexp(); }
	size_t record_count() const { return rrdata ? rrdata->record_count() : 0; }
	void add_record(dns_raw_msg msg, size_t offset) { rrdata->add_record(msg, offset); } // from DNS message
	void add_record(const uint8_t ** data, size_t * len) { rrdata->add_record(data, len); } // from cache, updates data and len
	static const rrset_rdata<default_rdata> empty_rrset;
	bool operator==(const dns_rrset & rr) const {
		if(name != rr.name) return false;
		if(rrdata == nullptr || rr.rrdata == nullptr) return rrdata == rr.rrdata;
		return *rrdata == *rr.rrdata;
	}
	bool operator!=(const dns_rrset & rr) const { return !(*this == rr); }
};


inline std::ostream &operator<<(std::ostream &out, const dns_rrset &r)
{
	out << r.name;
	if(r.rrdata != nullptr)
		out << ", RR data: " << *r.rrdata;
	else
		out << ", RR data: [nullptr]";
	return out;
}


#endif // DNS_RECORD_H
