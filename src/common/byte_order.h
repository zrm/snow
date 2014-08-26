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

#ifndef BYTE_ORDER_H
#define BYTE_ORDER_H
#ifdef WINDOWS
#include<winsock2.h>
#else
#include<arpa/inet.h>
#ifdef __linux
#include<endian.h>
#else
#include<sys/endian.h>
#endif
#endif
#include<cstdint>
#include<cstring>


#ifndef be64toh
inline uint64_t be64toh(uint64_t v)
{
	if(ntohl(0x12345678) == 0x12345678)
		return v;
	uint64_t rv = ntohl(v & 0xffffffff);
	rv <<= 32;
	rv += ntohl(v >> 32);
	return rv;
}
#endif
#ifndef htobe64
inline uint64_t htobe64(uint64_t v)
{
	if(htonl(0x12345678) == 0x12345678)
		return v;
	uint64_t rv = htonl(v & 0xffffffff);
	rv <<= 32;
	rv += htonl(v >> 32);
	return rv;
}
#endif

inline void read_bits(unsigned long) {} // terminate recursion
template<class FIRST, class... REST>
void read_bits(unsigned long data, FIRST *num, size_t first_size, REST... rest)
{
	unsigned long mask = (1 << first_size) - 1;
	*num = data & mask;
	read_bits(data >> first_size, rest...);
}

template<class DATA>
inline void write_bits(DATA &) {} // terminate recursion
template<class DATA, class FIRST, class... REST>
void write_bits(DATA &data, FIRST num, size_t first_size, REST... rest)
{
	data <<= first_size;
	unsigned long mask = (1 << first_size) - 1;
	data |= num & mask;
	write_bits(data, rest...);
}

// read_hbo: read sizeof(UINT) in network byte order, return after conversion to host byte order
template<class UINT> UINT read_hbo(const uint8_t *data);
// write_hbo: take val in host byte order, write to data in network byte order
template<class UINT> void write_hbo(UINT val, uint8_t *data);

// read_nbo: read sizeof(UINT) and return without doing any byte order conversion
template<class UINT> inline UINT read_nbo(const uint8_t * data) {
	UINT rv;
	memcpy(&rv, data, sizeof(rv));
	return rv;
}
// write_nbo: write val to data without doing any byte order conversion
template<class UINT> inline void write_nbo(UINT val, uint8_t * data) {
	memcpy(data, &val, sizeof(val));
}


#endif // BYTE_ORDER_H
