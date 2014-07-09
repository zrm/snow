/*	snow
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

#ifndef DHT_MSGTYPE_H
#define DHT_MSGTYPE_H
#include"../common/network.h"

// TODO: DHT messages should provide list of pluggable alternative transports to DTLS (e.g. CurveCP, IPSec) and allow for future improvements like a snow IP transport layer protocol
	// it is expected that every client should support DTLS (since it requires no kernel support), but others may be more efficient if available
	// probably the way to do this is to add an unused variable length field to the end of CONNECT that existing peers will ignore and can be used for future purposes
		// (this is now the variable_opaque_field RESERVED field in CONNECT)

typedef dht::DHTMSG DHTMSG;

template<typename ENUM, ENUM FIELD_NUM, class TYPE>
struct mate
{
	typedef TYPE type;
	static const ENUM num = FIELD_NUM;
	const TYPE& ref;
	mate(const TYPE& r) : ref(r) {}
};

/*
The following classes are effectively typed pointers to raw data fields provided by dhtmsg_base.
If the (uint8_t*) constructor is used (as it is in dhtmsg_base::get<X>()),
	well-defined behavior is only possible so long as the pointer remains valid, i.e. the dhtmsg object still exists.
In other words, don't pass one of these to another thread
	or store it in a container that survives a return from process_dhtmsg[_final]<>()
*/

template<class FIELD_CLASS, class FIELD_TYPE>
struct field_base
{
	FIELD_TYPE field;
	field_base(const FIELD_TYPE& f) : field(f) {}
	field_base(const uint8_t* raw) { memcpy(&field, raw, sizeof(field)); }
	// defaults (works for many fixed-length types stored in network byte order):
	static inline size_t size() { return sizeof(field); }
	static inline size_t size(const uint8_t*) { return sizeof(field); }
	inline void copy_to(uint8_t* to) const { memcpy(to, &field, sizeof(field)); }
};

// dynamic_field_base:
	// allow return by value
	// to a zero-copied object (ptr in object points to raw data)
	// that has a move constructor and move assignment operator that does a zero-copy move, and
	// a copy constructor that does a non-zero copy copy ('new' + flag for destructor to 'delete')
// then caller can do e.g. 'ip_addr addr = get<IP_ADDR>()' and have zero copy, but copy the obj again and it copies the data
	// which should be safe so long as 'addr' falls out of scope before raw buffer data is deleted/modified, essentially same as an iterator
template<class T>
class dynamic_field_base
{
protected:
	const uint8_t* field;
	bool dynamic;
	dynamic_field_base(const uint8_t* f, bool d) : field(f), dynamic(d) {}
public:
	dynamic_field_base(const uint8_t* raw) : field(raw), dynamic(false) {}
	dynamic_field_base(const T& c) : field(new uint8_t[c.size()]), dynamic(true) {
		memcpy(field, c.field, c.size());
	}
	dynamic_field_base(T&& c) : field(c.field), dynamic(c.dynamic) {
		c.dynamic = false;
	}
	T& operator=(T&& c) {
		std::swap(field, c.field);
		std::swap(dynamic, c.dynamic);
		return static_cast<T&>(*this);
	}
	~dynamic_field_base() { if(dynamic && field != nullptr) delete[] field; }
	inline void copy_to(uint8_t* to) const { memcpy(to, field, this->T::size()); }
};


// this turns out to be !useful for types containing non-length fixed fields because size() must always return at least size of fixed length fields
	// which means first two bytes must be (or indicate) size of variable data and size() must be { [fixed size] + [variable size] }
/*template<class T>
class variable_field_base : public dynamic_field_base<T>
{
	typedef dynamic_field_base<T> base;
protected:
	variable_field_base(const uint8_t* raw, bool Dynamic) : base(raw, Dynamic) {} // let subclass handle its own construction if necessary
public:
	// size for the wire
	static inline size_t size(const uint8_t* ptr) { return byte_order<uint16_t>(ptr).get_hbo(); }
	inline size_t size() const { return size(base::field); } 
	inline void copy_to(uint8_t* to) const { memcpy(to, base::field, size()); }
	variable_field_base(const uint8_t* raw) : base(raw) {}
};*/

// variable field base for fields with nothing other than variable data (no fixed width type(s) other than size preceding variable data)
template<class T>
struct variable_single_field_base : public dynamic_field_base<T>
{
	typedef dynamic_field_base<T> base;
	// size for the wire
	static inline size_t size(const uint8_t* ptr) { return byte_order<uint16_t>(ptr).get_hbo() + sizeof(uint16_t); }
	inline size_t size() const { return size(base::field); } 
	inline void copy_to(uint8_t* to) const { memcpy(to, base::field, size()); }
	inline size_t data_size() const { return byte_order<uint16_t>(base::field).get_hbo(); } // size of actual data (not including size header)
	const uint8_t* data() const { return base::field + sizeof(uint16_t); } // start of variable data (after size header)
	variable_single_field_base(const uint8_t* raw) : base(raw) {}
	variable_single_field_base(uint16_t len, const uint8_t* field_data) : base(nullptr, true) {
		uint8_t* newfield = new uint8_t[len + sizeof(uint16_t)]; // need non-const temporary to initialize
		byte_order<uint16_t>(len).write_nbo(newfield);
		memcpy(newfield+sizeof(uint16_t), field_data, len);
		base::field = newfield;
	}
};

// dht_header (important):
	// this is the first field in every dhtmsg (and so a lot of things will provide a whole dhtmsg to it as an argument, to read header values)
	// get_msglen must, like individual fields, always be able to provide the entire message length from the first two bytes (e.g. dht::read() or for FORWARD payload)
class dht_header : public field_base<dht_header, std::pair<uint16_t,uint16_t> >
{
	typedef field_base<dht_header, std::pair<uint16_t,uint16_t> > base;
public:
	inline static uint16_t get_msglen(dhtmsg m) { return get_msglen(m.msg); }
	inline static uint16_t get_msgtype(dhtmsg m) { return get_msgtype(m.msg); }
	inline static uint16_t get_msglen(const uint8_t* msg) { return byte_order<uint16_t>(msg).get_hbo(); }
	inline static uint16_t get_msgtype(const uint8_t* msg) { return byte_order<uint16_t>((msg+sizeof(uint16_t))).get_hbo(); }
	inline uint16_t get_msglen() { return ntohs(base::field.first); }
	inline uint16_t get_msgtype() { return ntohs(base::field.second); }
	dht_header(DHTMSG msgtype) : base(std::make_pair(0, htons(static_cast<uint16_t>(msgtype)))) {}
	dht_header(const uint8_t* raw) : base(raw) {}
	static_assert(sizeof(std::pair<uint16_t,uint16_t>)==2*sizeof(uint16_t), "unexpected padding in pair");
	void set_size(uint16_t sz) { base::field.first = htons(sz); }
};

struct dht_hash :  public dynamic_field_base<dht_hash>
{
	typedef dynamic_field_base<dht_hash> base;
	// size for the wire
	static inline size_t size(const uint8_t* ptr) { return byte_order<uint16_t>(ptr).get_hbo() + 2*sizeof(uint16_t); }
	inline size_t size() const { return size(base::field); } 
	inline void copy_to(uint8_t* to) const { memcpy(to, base::field, size()); }
	// size of actual variable data (not including size+algo header)
	inline size_t data_size() const { return byte_order<uint16_t>(base::field).get_hbo(); } 
	const uint8_t* data() const { return base::field + 2*sizeof(uint16_t); } // start of variable data (after size header and algorithm)
	uint16_t algo() const { return byte_order<uint16_t>(base::field+sizeof(uint16_t)).get_hbo(); }
	dht_hash(const uint8_t* raw) : base(raw) {}
	dht_hash(const hashkey& hk) : dht_hash(hk.algo(), hk.size(), hk.get_raw()) {}
	dht_hash(uint16_t algo_hbo, uint16_t datalen, const uint8_t* field_data) : base(nullptr, true) {
		size_t len = datalen + sizeof(datalen) + sizeof(algo_hbo);
		if(len > UINT16_MAX)
			throw std::out_of_range("excessive hash length in dht_hash");
		uint8_t* newfield = new uint8_t[len]; // need non-const temporary to initialize
		byte_order<uint16_t>(datalen).write_nbo(newfield); // set hash len
		byte_order<uint16_t>(algo_hbo).write_nbo(newfield+sizeof(datalen));
		memcpy(newfield+sizeof(datalen)+sizeof(algo_hbo), field_data, datalen);
		base::field = newfield;
	}
	hashkey get_hashkey() const { return hashkey(data(), algo(), data_size()); } // convenience method
};

struct dht_forward_payload : public variable_single_field_base<dht_forward_payload>
{
	typedef variable_single_field_base<dht_forward_payload> base;
	dht_forward_payload(const uint8_t* raw) : base(raw) {}
	dht_forward_payload(dhtmsg m) : base(m.msg) {}
	dhtmsg get_dhtmsg() const { return dhtmsg(base::field); }
};

// this allows an undefined variable-length field to be added to a dhtmsg for future use
// existing nodes will ignore the field and pass it along unmodified when routing messages
struct variable_opaque_data : public variable_single_field_base<variable_opaque_data>
{
	typedef variable_single_field_base<variable_opaque_data> base;
	variable_opaque_data(const uint8_t* raw) : base(raw) {}
	variable_opaque_data(dhtmsg m) : base(m.msg) {}
	variable_opaque_data() : base(0, nullptr) {}
};

class dht_ip_addrs : public dynamic_field_base<dht_ip_addrs>
{
	// alloc: allocate space for num ip_infos, return ptr to location first should be copied to
	uint8_t* alloc(size_t num) {
		if(num==0)
			throw std::out_of_range("dht_ip_addrs supplied with empty set of IP addresses");
		size_t len = sizeof(uint16_t) + num*ip_info::size();
		uint8_t* newfield = new uint8_t[len];
		byte_order<uint16_t>(num-1).write_nbo(newfield);
		field = newfield;
		return newfield + sizeof(uint16_t);
	}
public:
	dht_ip_addrs(const uint8_t* raw) : dynamic_field_base(raw) {}
	dht_ip_addrs(const std::vector<ip_info>& addrs) : dynamic_field_base(nullptr, true) {
		uint8_t* next = alloc(addrs.size());
		for(const ip_info& ip : addrs) {
			ip.copy_to(next);
			next += ip_info::size();
		}
	}
	dht_ip_addrs(const ip_info& ip) : dynamic_field_base(nullptr, true) {
		uint8_t* next = alloc(1);
		ip.copy_to(next);
	}

	inline size_t size() const { return size(field); }
	static inline size_t size(const uint8_t *raw) { return sizeof(uint16_t) + (byte_order<uint16_t>(raw).get_hbo() + 1) * ip_info::size(); }
	inline void copy_to(uint8_t* to) const { memcpy(to, field, size()); }
	std::vector<ip_info> get() {
		std::vector<ip_info> addrs;
		size_t num_addrs = byte_order<uint16_t>(field).get_hbo() + 1;
		const uint8_t *next = field + sizeof(uint16_t);
		for(size_t i=0; i < num_addrs; ++i){
			addrs.push_back(next);
			next += ip_info::size();
		}
		return addrs;
	}
};

template<class T>
class uint16_base : public field_base<T, uint16_t>
{
private:
	typedef field_base<T, uint16_t> base;
public:
	// simple uint16_t stored in network byte order
	uint16_base(uint16_t nbo_uint16) : base(nbo_uint16) {}
	uint16_base(const uint8_t* raw) : base(byte_order<uint16_t>(raw).get_nbo()) {}
	uint16_t get_nbo() { return base::field; }
	uint16_t get_hbo() { return ntohs(base::field); }
};

template<class T>
class uint64_base : public field_base<T, uint64_t>
{
private:
	typedef field_base<T, uint64_t> base;
public:
	// simple uint64_t stored in network byte order
	uint64_base(uint64_t nbo_uint64) : base(nbo_uint64) {}
	uint64_base(const uint8_t* raw) : base(byte_order<uint64_t>(raw).get_nbo()) {}
	uint64_t get_nbo() { return base::field; }
	uint64_t get_hbo() { return be64toh(base::field); }
};

class unix_time : public uint64_base<unix_time>
{
	typedef uint64_base<unix_time> base;
public:
	unix_time(uint64_t hbo_uint64) : base(byte_order<uint64_t>(hbo_uint64).get_nbo()) {}
	unix_time(const uint8_t* raw) : base(raw) {}
};

class nonce64 : public uint64_base<nonce64>
{
	typedef uint64_base<nonce64> base;
public:
	nonce64(uint64_t hbo_uint64) : base(byte_order<uint64_t>(hbo_uint64).get_nbo()) {}
	nonce64(const uint8_t* raw) : base(raw) {}
};

class trackback_route_id : public uint64_base<trackback_route_id>
{
	typedef uint64_base<trackback_route_id> base;
public:
	trackback_route_id(uint64_t hbo_uint64) : base(byte_order<uint64_t>(hbo_uint64).get_nbo()) {}
	trackback_route_id(const uint8_t* raw) : base(raw) {}
};


class dht_version : public uint16_base<dht_version>
{
	typedef uint16_base<dht_version> base;
public:
	dht_version(uint16_t hbo_uint16) : base(byte_order<uint16_t>(hbo_uint16).get_nbo()) {}
	dht_version(uint8_t* raw) : base(raw) {}
};

class ip_port : public uint16_base<ip_port>
{
	typedef uint16_base<ip_port> base;
public:
	ip_port(uint16_t nbo_uint16) : base(nbo_uint16) {}
	ip_port(const uint8_t* raw) : base(raw) {}
};

class dht_fieldlen : public uint16_base<dht_fieldlen>
{
	typedef uint16_base<dht_fieldlen> base;
public:
	dht_fieldlen(uint16_t hbo_uint16) : base(byte_order<uint16_t>(hbo_uint16).get_nbo()) {}
	dht_fieldlen(const uint8_t* raw) : base(raw) {}
};

class dht_fieldtype : public uint16_base<dht_fieldtype>
{
	typedef uint16_base<dht_fieldtype> base;
public:
	dht_fieldtype(uint16_t hbo_uint16) : base(byte_order<uint16_t>(hbo_uint16).get_nbo()) {}
	dht_fieldtype(const uint8_t* raw) : base(raw) {}
};

class dht_flags : public uint16_base<dht_flags>
{
	typedef uint16_base<dht_flags> base;
public:
	dht_flags(const uint8_t* raw) : base(raw) {}
	dht_flags() : base(static_cast<uint16_t>(0)) {}
	void setflag(unsigned flagnum) { field |= htons(1 << flagnum); }
	void clearflag(unsigned flagnum) { field &= ~htons(1 << flagnum); }
	bool getflag(unsigned flagnum) { return field & htons(1 << flagnum); }
};

class dht_hashalgo : public uint16_base<dht_hashalgo>
{
	typedef uint16_base<dht_hashalgo> base;
public:
	dht_hashalgo(uint16_t hbo_uint16) : base(byte_order<uint16_t>(hbo_uint16).get_nbo()) {}
	dht_hashalgo(const uint8_t* raw) : base(raw) {}
};




// dht_route_header is a helper and is not suitable for use as a dhtmsg_base template parameter
struct dht_route_header
{
	dht_hash hash;
	inline dht_route_header(dhtmsg m) : dht_route_header(m.msg) {}
	dht_route_header(const uint8_t* msg) : hash(msg+dht_header::size()) {}
	hashkey get_hashkey() { return hash.get_hashkey(); }
	inline static bool validate_route_header(dhtmsg m, uint16_t msglen) { return validate_route_header(m.msg, msglen); }
	static bool validate_route_header(const uint8_t* msg, uint16_t msglen) { 
		// check that we have enough to read hash size
		if( msglen < dht_header::size() + sizeof(uint16_t) )
			return false;
		// check that we have the whole destination hash
		if( msglen < dht_header::size() + dht_hash(msg+dht_header::size()).size() )
			return false;
		return true;
	}
};


template <uint16_t DEPTH, typename... ARGS> struct parse_type;

template <uint16_t DEPTH, class T, typename... ARGS>
struct parse_type<DEPTH, T, ARGS...> {
	static_assert(DEPTH < sizeof...(ARGS) + 1, "Requested field num that doesn't exist");
	typedef typename parse_type<DEPTH - 1, ARGS...>::type type;
	static const unsigned field_num = parse_type<DEPTH - 1, ARGS...>::field_num;
	static inline size_t data_size(const T field, ARGS... rest) {
		return field.ref.size() + parse_type<DEPTH-1, ARGS...>::data_size(rest...);
	}
	static inline void init_fields(const uint8_t** offsets, uint8_t* current_offset, const T field, ARGS... rest)
	{
		*offsets = current_offset;
		field.ref.copy_to(current_offset);
		parse_type<DEPTH-1, ARGS...>::init_fields(++offsets, current_offset + field.ref.size(), rest...);
	}
	static inline void init_offsets(const uint8_t** offsets, const uint8_t* current_offset) {
		*offsets = current_offset;
		parse_type<DEPTH-1, ARGS...>::init_offsets(++offsets, current_offset + T::type::size(current_offset));
	}
	static inline bool validate(const uint8_t* msg_offset, uint16_t remainder) {
		size_t field_size = T::type::size(msg_offset); 
		// give the next level at least two bytes, so it's safe to read size of variable length types
			// this means each field must be at least two bytes (or validation will consider invalid), but that's a tolerable constraint
		if(remainder < field_size + 2)
			return false;
		return parse_type<DEPTH-1, ARGS...>::validate(msg_offset + field_size, remainder - field_size);
	}
};

template <class T, typename... ARGS>
struct parse_type<0, T, ARGS...> {
	typedef typename T::type type;
	static const unsigned field_num = static_cast<unsigned>(T::num);
	static inline type& get(const T field, ARGS...) { return field.ref; }
	static inline size_t data_size(T field) {
		return field.ref.size();
	}
	// don't take 'ARGS...' here because there should never be any left by this point:
	static inline void init_fields(const uint8_t** offsets, uint8_t* current_offset, const T field)
	{
		*offsets=current_offset;
		field.ref.copy_to(current_offset);
	}
	static inline void init_offsets(const uint8_t** offsets, const uint8_t* current_offset)
	{
		*offsets = current_offset;
	}
	static inline bool validate(const uint8_t* msg_offset, uint16_t remainder) {
		return remainder == T::type::size(msg_offset); 
	}
};

template<DHTMSG MSGTYPE, class... FORMAT>
class dhtmsg_base
{
private:
	const uint8_t* field_offset[sizeof...(FORMAT)];
	const uint8_t* data;
	uint8_t* dynamic_data; // this is data if data is dynamically allocated and owned by this object, nullptr otherwise
	typedef parse_type<sizeof...(FORMAT) - 1, FORMAT...> parse_type_format;
protected:
	static const DHTMSG msgtype = MSGTYPE;
public:
	typedef typename dht::msg_enum<MSGTYPE>::FIELDS FIELD;
	dhtmsg_base(FORMAT... input) {
		size_t msg_size = parse_type_format::data_size(input...);
		if(msg_size <= UINT16_MAX) {
			dynamic_data = new uint8_t[msg_size];
			parse_type_format::init_fields(field_offset, dynamic_data, input...);
			dht_header header(dynamic_data);
			header.set_size(msg_size);
			header.copy_to(dynamic_data);
			data = dynamic_data;
		} else {
			// message is too large, would overflow message size field
			// this message is now a NOP
			// TODO: consider better ways of handling this
			wout() << "dhtmsg would have overflowed message size field, converted to NOP";
			dynamic_data = new uint8_t[dht_header::size()];
			dht_header header(DHTMSG::NOP);
			header.set_size(dht_header::size());
			header.copy_to(dynamic_data);
			data = dynamic_data;
		}
	}
	dhtmsg_base(dhtmsg m) : dhtmsg_base(m.msg) {}
	dhtmsg_base(const uint8_t* raw) :  data(raw), dynamic_data(nullptr) {
		parse_type_format::init_offsets(field_offset, data);
	}
	dhtmsg_base(const dhtmsg_base&) = delete; // could implement this (but probably not trivially), and don't need it, so just make sure nothing uses it
	template<typename dht::msg_enum<MSGTYPE>::FIELDS FIELD_ENUM>
	typename parse_type<static_cast<uint16_t>(FIELD_ENUM), FORMAT...>::type get() const {
		// TODO: equivalent of this static_assert on the constructor side / parse_type side
		static_assert(static_cast<uint16_t>(FIELD_ENUM) == parse_type<static_cast<uint16_t>(FIELD_ENUM), FORMAT...>::field_num,
			"Field enum mismatch with offset field number. Check that dhtmsg_base template argument order corresponds to enum order.");
		return typename parse_type<(uint16_t)FIELD_ENUM, FORMAT...>::type(field_offset[(unsigned)FIELD_ENUM]);
	}
	template<typename dht::msg_enum<MSGTYPE>::FIELDS FIELD_ENUM>
	void set(const typename parse_type<static_cast<uint16_t>(FIELD_ENUM), FORMAT...>::type& arg) {
		if(dynamic_data == nullptr) {
			// data is const, have to reallocate
			size_t msglen = dht_header::get_msglen(data);
			dynamic_data = new uint8_t[msglen];
			memcpy(dynamic_data, data, msglen);
			data = dynamic_data;
			// field offset pointers still point to old const data, update
			parse_type_format::init_offsets(field_offset, dynamic_data);
		}
		// now const_cast is OK because data == non-const dynamic_data 
		arg.copy_to(const_cast<uint8_t*>(field_offset[static_cast<uint16_t>(FIELD_ENUM)]));
		
		if(!sizeof(parse_type<static_cast<uint16_t>(FIELD_ENUM), FORMAT...>::type::size())) {
			/* dhtmsg_base::set is not correctly implemented for variable length field types (because it assumes the new field is the same length as the old one),
			 this if statement will produce an intentional compile error if you instantiate its template for a variable length field (i.e. with non-static size function) */
		}
	}

	static bool validate(dhtmsg dmsg) {
		size_t msglen = dht_header::get_msglen(dmsg.msg);
		return parse_type_format::validate(dmsg.msg, msglen);
	}
	dhtmsg get_msg() { return dhtmsg(data); }
	~dhtmsg_base() { if(dynamic_data != nullptr) delete dynamic_data; }
};

template<DHTMSG MSGTYPE>
struct dhtmsg_enum;
template<DHTMSG MSGTYPE, typename ENUM>
struct dhtmsg_intermediate;

template<DHTMSG MSGTYPE>
struct dhtmsg_type : public dhtmsg_intermediate<MSGTYPE, typename dht::msg_enum<MSGTYPE>::FIELDS >
{
	typedef dhtmsg_intermediate<MSGTYPE, typename dht::msg_enum<MSGTYPE>::FIELDS > base;
	// check template specializations:
	template<typename... C> static uint8_t test_base(dhtmsg_base<MSGTYPE, C...>*);
	template<typename... C> static uint16_t test_base(...);
	// TODO: this assertion passes with gcc but fails when it should not with clang 3.3, figure out if problem is with assertion or clang
	static_assert(sizeof(decltype(test_base(static_cast<dhtmsg_type<MSGTYPE>*>(nullptr)))) == sizeof(uint8_t),
		"dhtmsg_intermediate<DHTMSG> template specialization is malformed or missing, check \" : public dhtmsg_base<...>\" template arguments and ensure dhtmsg_intermediate is derived from dhtmsg_base");
	static_assert(MSGTYPE==base::msgtype, "dhtmsg_intermediate template specialization contains DHTMSG type mismatch");
	
	inline dhtmsg_type(dhtmsg msg) : dhtmsg_type::dhtmsg_intermediate(msg) {}
	template<typename...Args> inline dhtmsg_type(Args&&... args) : dhtmsg_type::dhtmsg_intermediate(dht_header(MSGTYPE), std::forward<Args>(args)...) {}
};

/*
 * Message format specifications work as follows:
 * 1) Specialize dht::msg_enum's DHTMSG template parameter and define a strongly typed enum that contains the names of the fields for the message type
 * 2) Specialize dhtmsg_intermediate, inheriting from dhtmsg_base and providing ordered pairs that 'mate' field name enums with types
 * 3) The body of dhtmsg_intermediate should contain this, to allow dhtmsg_base constructors to be visible:
 *		template<class...Args> inline dhtmsg_intermediate(Args&&... args) : dhtmsg_intermediate::dhtmsg_base(std::forward<Args>(args)...) {}
 *		TODO: Do this instead when newer compilers (e.g. gcc 4.8+) are adopted by all platforms:
 *		using dhtmsg_base::dhtmsg_base;
 * 4) dhtmsg_intermediate specializations may contain any useful helper functions specific to that message type, if desired
 */


template<> struct dht::msg_enum<DHTMSG::CONNECT>
	{enum class FIELDS {HEADER, DEST_HASHKEY, ROUTE_ID, FLAGS, TARGET_HASHKEY, IP_ADDRS, SRC_PORT, RESERVED}; };
template<typename F> struct dhtmsg_intermediate<DHTMSG::CONNECT, F> :
	public dhtmsg_base<	DHTMSG::CONNECT,
		mate<F, F::HEADER, dht_header>,
		mate<F, F::DEST_HASHKEY, dht_hash>,
		mate<F, F::ROUTE_ID, trackback_route_id>,
		mate<F, F::FLAGS, dht_flags>,
		mate<F, F::TARGET_HASHKEY, dht_hash>,
		mate<F, F::IP_ADDRS, dht_ip_addrs>,
		mate<F, F::SRC_PORT, ip_port>,
		mate<F, F::RESERVED, variable_opaque_data> >
{	inline dhtmsg_intermediate(dhtmsg msg) : dhtmsg_intermediate::dhtmsg_base(msg) {}
	inline dhtmsg_intermediate(const uint8_t* raw) : dhtmsg_intermediate::dhtmsg_base(raw) {}
	// cheat here a little bit so callers don't have to provide variable_opaque_data()
	template<class...Args> inline dhtmsg_intermediate(Args&&... args) : dhtmsg_intermediate::dhtmsg_base(std::forward<Args>(args)..., variable_opaque_data()) {} };

template<> struct dht::msg_enum<DHTMSG::HOLEPUNCH_ADDRS>
	{enum class FIELDS {HEADER, DEST_HASHKEY, ROUTE_ID, IP_ADDRS}; };
template<typename F> struct dhtmsg_intermediate<DHTMSG::HOLEPUNCH_ADDRS, F> :
	public dhtmsg_base<	DHTMSG::HOLEPUNCH_ADDRS,
		mate<F, F::HEADER, dht_header>,
		mate<F, F::DEST_HASHKEY, dht_hash>,
		mate<F, F::ROUTE_ID, trackback_route_id>,
		mate<F, F::IP_ADDRS, dht_ip_addrs> >
{ template<class...Args> inline dhtmsg_intermediate(Args&&... args) : dhtmsg_intermediate::dhtmsg_base(std::forward<Args>(args)...) {} };

template<> struct dht::msg_enum<DHTMSG::MISMATCH_DETECTED>
	{enum class FIELDS {HEADER, DEST_HASHKEY, ROUTE_ID, TARGET_HASHKEY}; };
template<typename F> struct dhtmsg_intermediate<DHTMSG::MISMATCH_DETECTED, F> :
	public dhtmsg_base<	DHTMSG::MISMATCH_DETECTED,
		mate<F, F::HEADER, dht_header>,
		mate<F, F::DEST_HASHKEY, dht_hash>,
		mate<F, F::ROUTE_ID, trackback_route_id>,
		mate<F, F::TARGET_HASHKEY, dht_hash> >
{ template<class...Args> inline dhtmsg_intermediate(Args&&... args) : dhtmsg_intermediate::dhtmsg_base(std::forward<Args>(args)...) {} };

template<> struct dht::msg_enum<DHTMSG::CHECK_ROUTE> {enum class FIELDS {HEADER, DEST_HASHKEY, NONCE, ROUTE_ID}; };
template<typename F> struct dhtmsg_intermediate<DHTMSG::CHECK_ROUTE, F> : public dhtmsg_base<DHTMSG::CHECK_ROUTE,
		mate<F, F::HEADER, dht_header>,
		mate<F, F::DEST_HASHKEY, dht_hash>,
		mate<F, F::NONCE, nonce64>,
		mate<F, F::ROUTE_ID, trackback_route_id> >
{ template<class...Args> inline dhtmsg_intermediate(Args&&... args) : dhtmsg_intermediate::dhtmsg_base(std::forward<Args>(args)...) {} };

template<> struct dht::msg_enum<DHTMSG::TRACKBACK_FORWARD> {enum class FIELDS { HEADER, DEST_HASHKEY, ROUTE_ID, PAYLOAD }; };
template<typename F> struct dhtmsg_intermediate<DHTMSG::TRACKBACK_FORWARD, F> : public dhtmsg_base<DHTMSG::TRACKBACK_FORWARD,
		mate<F, F::HEADER, dht_header>,
		mate<F, F::DEST_HASHKEY, dht_hash>,
		mate<F, F::ROUTE_ID, trackback_route_id>,
		mate<F, F::PAYLOAD, dht_forward_payload> >
{ template<class...Args> inline dhtmsg_intermediate(Args&&... args) : dhtmsg_intermediate::dhtmsg_base(std::forward<Args>(args)...) {} };

template<> struct dht::msg_enum<DHTMSG::FORWARD> {enum class FIELDS {HEADER, DEST_HASHKEY, PAYLOAD}; };
template<typename F> struct dhtmsg_intermediate<DHTMSG::FORWARD, F> : public dhtmsg_base<DHTMSG::FORWARD,
		mate<F, F::HEADER, dht_header>,
		mate<F, F::DEST_HASHKEY, dht_hash>,
		mate<F, F::PAYLOAD, dht_forward_payload> >
{ template<class...Args> inline dhtmsg_intermediate(Args&&... args) : dhtmsg_intermediate::dhtmsg_base(std::forward<Args>(args)...) {} };




template<> struct dht::msg_enum<DHTMSG::HELLO> {enum class FIELDS {HEADER, TIME, NONCE, PROTOCOL_VERSION}; };
template<typename F> struct dhtmsg_intermediate<DHTMSG::HELLO, F> : public dhtmsg_base<DHTMSG::HELLO,
		mate<F, F::HEADER, dht_header>,
		mate<F, F::TIME, unix_time>,
		mate<F, F::NONCE, nonce64>,
		mate<F, F::PROTOCOL_VERSION, dht_version> >
{ template<class...Args> inline dhtmsg_intermediate(Args&&... args) : dhtmsg_intermediate::dhtmsg_base(std::forward<Args>(args)...) {} };


// CHECK_ROUTE_OK: signifies that CHECK_ROUTE was properly routed to the connected peer
template<> struct dht::msg_enum<DHTMSG::CHECK_ROUTE_OK> {enum class FIELDS { HEADER }; };
template<typename F> struct dhtmsg_intermediate<DHTMSG::CHECK_ROUTE_OK, F> : public dhtmsg_base<DHTMSG::CHECK_ROUTE_OK,
		mate<F, F::HEADER, dht_header> >
{ template<class...Args> inline dhtmsg_intermediate(Args&&... args) : dhtmsg_intermediate::dhtmsg_base(std::forward<Args>(args)...) {} };

template<> struct dht::msg_enum<DHTMSG::TRACKBACK_ROUTE> {enum class FIELDS { HEADER, ROUTE_ID, PAYLOAD }; };
template<typename F> struct dhtmsg_intermediate<DHTMSG::TRACKBACK_ROUTE, F> : public dhtmsg_base<DHTMSG::TRACKBACK_ROUTE,
		mate<F, F::HEADER, dht_header>,
		mate<F, F::ROUTE_ID, trackback_route_id>,
		mate<F, F::PAYLOAD, dht_forward_payload> >
{ template<class...Args> inline dhtmsg_intermediate(Args&&... args) : dhtmsg_intermediate::dhtmsg_base(std::forward<Args>(args)...) {} };

template<> struct dht::msg_enum<DHTMSG::NOP> {enum class FIELDS { HEADER }; };
template<typename F> struct dhtmsg_intermediate<DHTMSG::NOP, F> : public dhtmsg_base<DHTMSG::NOP,
		mate<F, F::HEADER, dht_header> >
{ template<class...Args> inline dhtmsg_intermediate(Args&&... args) : dhtmsg_intermediate::dhtmsg_base(std::forward<Args>(args)...) {} };

template<> struct dht::msg_enum<DHTMSG::GOODBYE_REQUEST> {enum class FIELDS {HEADER }; };
template<typename F> struct dhtmsg_intermediate<DHTMSG::GOODBYE_REQUEST, F> : public dhtmsg_base<DHTMSG::GOODBYE_REQUEST,
		mate<F, F::HEADER, dht_header> >
{ template<class...Args> inline dhtmsg_intermediate(Args&&... args) : dhtmsg_intermediate::dhtmsg_base(std::forward<Args>(args)...) {} };

template<> struct dht::msg_enum<DHTMSG::GOODBYE_CONFIRM> {enum class FIELDS {HEADER }; };
template<typename F> struct dhtmsg_intermediate<DHTMSG::GOODBYE_CONFIRM, F> : public dhtmsg_base<DHTMSG::GOODBYE_CONFIRM,
		mate<F, F::HEADER, dht_header> >
{ template<class...Args> inline dhtmsg_intermediate(Args&&... args) : dhtmsg_intermediate::dhtmsg_base(std::forward<Args>(args)...) {} };



#endif // DHT_MSGTYPE_H
