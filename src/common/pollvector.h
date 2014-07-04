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

#ifndef POLLVECTOR_H
#define POLLVECTOR_H
#include<cstdint>
#ifdef WINSOCK
#include<Winsock2.h>
#include<memory>
#include"common.h"
#else
#include<poll.h>
#endif
#include<functional>
#include<algorithm>
#include"../common/network.h"
#include"../common/err_out.h"


// events supported by pollvector
class pvevent
{
#ifdef WINSOCK
	long event;
#else
	uint32_t event;
#endif
	pvevent(int e) : event(e) {}
	template<class> friend class pollvector;
public:
	pvevent(const pvevent &p) = default;
	static const pvevent none;
	static const pvevent read;
	static const pvevent write;
	static const pvevent error;
	pvevent operator|(pvevent p) const { return pvevent(event | p.event); }
	pvevent operator|=(pvevent p) { event |= p.event; return *this; }
	pvevent operator^(pvevent p) const { return pvevent(event ^ p.event); }
	pvevent operator^=(pvevent p) { event ^= p.event; return *this; }
	pvevent operator&(pvevent p) const { return pvevent(event & p.event); }
	pvevent operator&=(pvevent p) { event &= p.event; return *this; }
	operator bool() const { return event != 0; }
};

#ifdef WINSOCK
struct wsa_event
{
	WSAEVENT ev;
	wsa_event() : ev(WSACreateEvent()) {
		if(ev == WSA_INVALID_EVENT)
			throw e_check_sock_err("WSACreateEvent");
	}
	void event_select(SOCKET sock, long events) {
		if(WSAEventSelect(sock, ev, events) != ERROR_SUCCESS)
			throw e_check_sock_err("WSAEventSelect");
	}
	~wsa_event() {
		if(ev != WSA_INVALID_EVENT)
			if(WSACloseEvent(ev) == false)
				dout() << "Failed to close WSA event in destructor: " << sock_err::get_last();
	}
	wsa_event(wsa_event &&we) : ev(we.ev) { we.ev = WSA_INVALID_EVENT; }
	wsa_event& operator=(wsa_event &&we) { std::swap(ev, we.ev); return *this; }
};
#endif

// different OS provide different polling functions (select/poll/epoll/kqueue), and the most widely supported ones are terrible (e.g. select())
// so this creates an abstraction around them all with an interface that can take advantage of epoll/kqueue and then uses internally whatever is supported
// constructor takes a cleanup function which will be called whenever an object is purged, to do whatever cleanup operations may be necessary
// second constructor arg is a lower bound for 'fixed' elements that should never be removed (e.g. listen socket), which must be added as the first elements
// template arg <T> is whatever arbitrary data you want to associate with each of the poll fds which will allow you to make use of events
	// it is often sensible to use a pointer, which can optionally be freed in cleanup, or a shared_ptr or unique_ptr, but you can also just store whatever directly
// when adding a new sd, call emplace_back() providing the sd (or SOCKET), the events to poll for, the callback to receive events, and constructor args for <T>
// the callback takes args as the pvevent that occurred, the index of the source of the event which can be used to get <T> or the fd, and a sock_err in case pvevent is error
// you may then call event_exec_wait() to block until some event(s) occur and then execute their callbacks, at which point it returns and allows you to do whatever or call again
// to remove an element, call mark_defunct() on its index, which does not remove the element or invalidate indexes but schedules removal
	// the element is then removed outside of any event callback before return from event_exec_wait, inhibiting indexes from being invalidated unexpectedly
template<class T>
class pollvector
{
// Windows implementation of this is ugly because Windows doesn't have anything resembling epoll/kqueue and windows poll/select have unreasonable limitations (WSAPoll is just broken and select has memory usage proportional to static max FD)
	// solution seems to be: use WSACreateEvent and WSAEventSelect in combination with RegisterWaitForSingleObject
	// then pass a tqueue as the context arg, and block event_exec_wait waiting for tqueue (using e.g. select(), or WaitForSingleObject())
		// when event is signaled it asynchronously puts data identifying event in tqueue and event_exec_wait thread processes it
		// this seems to sort everything: allows use of both file descriptors and sockets, is async instead of polling, allows arbitrarily large number of wait events, etc.
		// primary disadvantage is locking, but maybe do some profiling to see if it's serious (or implement lock-free tqueue)
#if defined(PV_USE_EPOLL)
	int epfd;
#elif defined(PV_USE_KQUEUE)
	int kq;
#elif defined(WINSOCK)
	struct winsock_peer {
		pollvector<T>* pv;
		std::shared_ptr<size_t> index;
		HANDLE wait_handle;
		winsock_peer(pollvector<T>* p, std::shared_ptr<size_t>& idx, WSAEVENT event_handle) : pv(p), index(idx), wait_handle(INVALID_HANDLE_VALUE) {
			if(RegisterWaitForSingleObject(&wait_handle, event_handle, &pollvector<T>::winsock_event_callback, (PVOID)this, INFINITE, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD) == SOCKET_ERROR)
				throw check_err_exception("winsock_peer(): RegisterWaitForSingleObject");
		}
		winsock_peer(pollvector<T>* p, std::shared_ptr<size_t>& idx) : pv(p), index(idx), wait_handle(INVALID_HANDLE_VALUE) {}
		~winsock_peer() {
			if(wait_handle != INVALID_HANDLE_VALUE)
				eout() << "BUG: did not unregister registered wait handle before winsock_peer destructor";
		}
	};
	struct winsock_event {
		winsock_peer* peer;
		enum { EVENT_OCCURRED, EVENT_CANCELED, FORCE_READ, FORCE_WRITE } event;
	};
	tqueue<winsock_event> event_tqueue;
	static VOID CALLBACK winsock_event_callback(PVOID wsp, BOOLEAN /*timer expired, always false as timer is INFINTE*/) {
		dout() << "winsock_event_callback()";
		winsock_peer* ws_peer = (winsock_peer*)wsp;
		ws_peer->pv->event_tqueue.put(winsock_event{ws_peer, winsock_event::EVENT_OCCURRED});
	}
	void cancel_events(size_t index);
	void process_winsock_event(winsock_event&& ev);
#else // poll()
	// poll() requires an array of pollfd, which means we can't just put pollfd in whatever object, it needs its own array/vector that needs to stay synced with associated data
	std::vector<pollfd> poll;
#endif

	struct pv_data {
		T tdata;
		std::function<void(size_t,pvevent,sock_err)> event_fn;
#ifdef WINSOCK
		pvevent events;
		SOCKET sock;
		wsa_event event_handle;
		std::shared_ptr<size_t> index;
		winsock_peer *peer_id;
		pv_data(T &&t, const std::function<void(size_t,pvevent,sock_err)> &f, SOCKET s, size_t idx)
			: tdata(std::forward<T>(t)), event_fn(f), events(pvevent::none), sock(s), index(new size_t(idx)), peer_id(nullptr) {}
#else
		pv_data(T &&t, const std::function<void(size_t,pvevent,sock_err)> &f) : tdata(std::forward<T>(t)), event_fn(f) {}
#endif
		// + xyz implementation specific data for various others, e.g. sock fd
	};
	std::vector<pv_data> data;
	std::vector<size_t> defunct_connections;
	std::function<void(size_t)> cleanup_handler; 
	size_t dynamic_start; // index of first non-static entry (below which none should ever be removed)
	std::string pvname;
	void reorder_remove(size_t index);
	// note: cleanup_defunct_connections() also invalidates indexes of elements *not* being removed
	bool cleanup_defunct_connections();
public:
	pollvector(const std::function<void(size_t)> &cleanup, size_t min_dynamic_start, const char* pv_name) : cleanup_handler(cleanup), dynamic_start(min_dynamic_start), pvname(pv_name) {}
	~pollvector();
	T& operator[](size_t index) {
		if(index >= size()) {
			eout() << pvname << ": access to pollvector element (" << index << ") outside of bounds (" << size() << ")";
			abort();
		}
		return data[index].tdata;
	}
	template<class... Args>
	void emplace_back(csocket::sock_t sock, pvevent event, const std::function<void(size_t,pvevent,sock_err)> &eventfn, Args&&... args);
	T& back() { return data.back().tdata; }
	size_t size() { return data.size(); }
	void event_exec_wait(int timeout);
	void set_fd(size_t index, csocket::sock_t fd);
	csocket::sock_t get_fd(size_t index);
	void set_events(size_t index, pvevent events);
	void add_events(size_t index, pvevent events);
	void clear_events(size_t index, pvevent events);
	void set_event_function(size_t index, const std::function<void(size_t,pvevent,sock_err)> &fn) { data[index].event_fn = fn; }
#ifdef WINSOCK
	// these two are safe to call from any thread:
	void indicate_read(size_t index) {
		event_tqueue.put(winsock_event{new winsock_peer(this, data[index].index), winsock_event::FORCE_READ});
	}
	void indicate_write(size_t index) {
		event_tqueue.put(winsock_event{new winsock_peer(this, data[index].index), winsock_event::FORCE_WRITE});
	}
#endif // WINSOCK
	void mark_defunct(size_t index);
};

#include "pollvector.tpp"
#endif // POLLVECTOR_H
