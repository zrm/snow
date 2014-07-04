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

#ifndef TUNTAP_H
#define TUNTAP_H
#include "../common/dbuf.h"
#ifdef WINDOWS
#include<functional>
#include<Windows.h>
#endif


class tuntap
{
#ifdef WINDOWS
	// TODO: there is no strong reason why multiple (e.g. 20) async send operations can't be made to the tuntap interface before returning EWOULDBLOCK and dropping packets
		// (assuming the driver is tolerant of this) [the trouble is allocating new OVERLAPPED and dbuf objects w/o reallocation, but could just allocate max to begin with]
		// this would be pretty easy to do: just change bool indicating whether async send is in progress to counter indicating how many (and thus whether in excess of threshold)
	HANDLE fd;
	std::string adapter_GUID;
	dbuf recv_buf;
	dbuf send_buf;
	OVERLAPPED recv_overlapped;
	OVERLAPPED send_overlapped;
	HANDLE recv_event;
	HANDLE recv_wait;
	// due to brain damage in Microsoft Windows, overlapped operations may nonetheless complete synchronously under unspecified conditions,
		// in which case using HasOverlappedIoCompleted and/or GetOverlappedResult to determine if the most recent operation has completed is insufficient or possibly dangerous
	// to avoid this, if a receive completes synchronously, received_sync will be the nonzero byte count of bytes synchronously received in recv_buf
		// if zero bytes are received synchronously then another call to ReadFile is made until either nonzero bytes are received or read is occurring asynchronously
		// this way a zero value indicates that the previous read was async, whereas a nonzero value indicates sync and provides the byte count
	// whereas if a send completes synchronously, sent_sync is set to true to indicate that another send can be made immediately
	// this leaves the theoretical trouble that a send or receive that should be async will block for a long time doing a synchronous operation
		// the solution for this would be to create separate tuntap send and receive threads for windows (at which point they might as well just be entirely synchronous)
		// but such can be deferred until behavior that pathological is actually observed in practice
	DWORD received_sync;
	bool sent_sync; 
	std::function<void()> read_ready_cb;
	static VOID CALLBACK read_event_cb(PVOID param, BOOLEAN ignored);
	void do_read();
	void do_write(size_t len);
#else
	int fd;
#endif
	unsigned mtu;
public:
// TODO: set_read_ready_cb should probably be a constructor arg, and read_ready_cb be const, since it is called asynchronously without locking
	// currently the trouble is that it is constructed in vnet but vnet doesn't have access to the sockets pollvector to create the callback
#ifdef WINDOWS
	HANDLE get_fd() { return fd; }
	// set_read_ready_cb is to be called once, before any call to recv_packet(), as the callback is used asynchronously w/o locking
	void set_read_ready_cb(const std::function<void()> &cb, size_t default_bufsize); 
	// (no write ready cb because writes are always directly in response to TLS reads and if they can't complete immediately then packet is dropped)
#else
	int get_fd() { return fd; }
#endif
	tuntap();
	~tuntap();
	// note: both recv_packet *AND* send_packet may modify the buffer passed
	// in particular, for async I/O the buffer will be swapped for a different one
		// the modified buffer may be equal or larger in size than the original but not smaller, and may point to different memory
	// recv_packet: writes received packet to buf, returns packet size
		// if no packet is available, return value is zero
		// on error, throws check_err_exception
	size_t recv_packet(dbuf &buf);
	// send_packet: sends packet in buf, of length len (which may be smaller than buf.size())
		// returns true if packet was sent, false if EWOULDBLOCK
		// on error, throws check_err_exception
	bool send_packet(dbuf &buf, size_t len);
	struct if_info {
		uint32_t if_addr;
		uint32_t netmask;
	};
	if_info get_if_info();
	unsigned get_mtu() { return mtu; } // reentrant
};

#endif // TUNTAP_H
