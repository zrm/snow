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

#ifndef COMMON_H
#define COMMON_H
#include<iostream>
#include<vector>
#include<mutex>
#include<condition_variable>
#include<functional>
#include<queue>
#include<sstream>
#include<algorithm>
#include<string>
#include<cstring>
#include<iomanip>
#include<random>
#ifdef WINDOWS
#include<winsock2.h>
#include<in6addr.h>
#else
#ifdef __linux
#include<endian.h>
#else
#include<sys/endian.h>
#endif
#include<sys/select.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<poll.h>
#endif

#include"../common/err_out.h"
#include"../common/network.h"

/* common.h: misc. small things that have no other home, probably should separate */

template<class UINT_T>
UINT_T getrand()
{
	static std::uniform_int_distribution<UINT_T> dist;
	static std::random_device rd;
	return dist(rd);
}

// std::equal does loose type checking for pointers (e.g. no complaints if you pass uint8_t* and uint16_t* to compare),
// and the syntax is somewhat lacking for pointers-as-iterators (pointer arithmetic bah)
template<class T, class U>
inline bool is_equal(const T* a, const U* b, size_t object_count) {
	static_assert(std::is_same<T,U>::value, "is_equal demands identical types, use std::equal or casts if you're sure");
	return std::equal(a, a + object_count, b);
}

template<>
inline bool is_equal<uint8_t, uint8_t>(const uint8_t* a, const uint8_t* b, size_t bytes) {
	// TODO: see if this is any faster/slower than std::equal
	return memcmp(a, b, bytes) == 0;
}

// this is assuming UTF-8 (or ASCII), hopefully everything else will cease to exist soon
inline uint8_t base32_to_raw(char c)
{
	if(c >= 'a' && c <= 'z')
		return c-'a';
	if(c >= '2' && c <= '7')
		return c - '2' + 26;
	if(c < 'A' || c > 'Z') {
		dout() << "base32_to_raw got invalid input: " << c;
		throw e_invalid_input("base32_to_raw");
	}
	return c-'A';
}
inline void base32_encode(const uint8_t data[5], char out[8])
{
	uint64_t stack = data[0];
	for(unsigned i = 1; i < 5; ++i) {
		stack <<= 8;
		stack += data[i];
	}
	uint8_t c = stack & 0x1f;
	out[7] = (c < 26) ? 'a'+c : '2'+c-26;
	for(int i = 6; i >= 0; --i) {
		stack >>= 5;
		c = stack & 0x1f;
		out[i] = (c < 26) ? 'a'+c : '2'+c-26;
	}
}
inline void base32_decode(const char in[8], uint8_t data_out[5])
{
	uint64_t stack = base32_to_raw(in[0]);
	for(unsigned i = 1; i < 8; ++i) {
		stack <<= 5;
		stack += base32_to_raw(in[i]);
	}
	data_out[4] = stack & 0xff;
	for(int i = 3; i >= 0; --i) {
		stack >>= 8;
		data_out[i] = stack & 0xff;
	}
}

template<typename T> class byte_order;

template<> class byte_order<uint16_t>
{
private:
	uint16_t val; // network byte order
public:
	byte_order(uint16_t v) : val(htons(v)) {}
	byte_order(const uint8_t* raw_nbo) { memcpy(&val, raw_nbo, sizeof(val)); }
	uint16_t get_hbo() { return ntohs(val); }
	uint16_t get_nbo() { return val; }
	void write_nbo(uint8_t* to_nbo) { memcpy(to_nbo, &val, sizeof(val)); }
};

template<> class byte_order<uint32_t>
{
private:
	uint32_t val; // network byte order
public:
	byte_order(uint32_t v) : val(htonl(v)) {}
	byte_order(const uint8_t* raw_nbo) { memcpy(&val, raw_nbo, sizeof(val)); }
	uint32_t get_hbo() { return ntohl(val); }
	uint32_t get_nbo() { return val; }
	void write_nbo(uint8_t* to_nbo) { memcpy(to_nbo, &val, sizeof(val)); }
};

#ifndef be64toh
inline uint64_t be64toh(uint64_t v)
{
	if(ntohl(1) == 1)
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
	if(htonl(1) == 1)
		return v;
	uint64_t rv = htonl(v & 0xffffffff);
	rv <<= 32;
	rv += htonl(v >> 32);
	return rv;
}
#endif

template<> class byte_order<uint64_t>
{
private:
	uint64_t val; // network byte order
public:
	byte_order(uint64_t v) : val(htobe64(v)) {}
	uint64_t get_hbo() { return be64toh(val); }
	byte_order(const uint8_t* raw_nbo) { memcpy(&val, raw_nbo, sizeof(val)); }
	uint64_t get_nbo() { return val; }
	void write_nbo(uint8_t* to_nbo) { memcpy(to_nbo, &val, sizeof(val)); }
};


// this is useful for deferring execution of something until this object falls out of scope
// but some amount of care is required in choosing something that will execute during stack unwinding
// (not currently used)
/*struct execute_on_destruction
{
	std::vector< std::function<void()> > functions;
	~execute_on_destruction() {
		for(auto &f : functions)
			f();
	}
};*/


// timer_queue: add() takes number of seconds or struct timeval and std::function
// exec() allows for subsequent synchronous execution of provided function after at least specified time period has elapsed
// TODO: timer_queue optimization: timers that take 'this' ptr of surrounding class are extremely common
	// so add template arg for surrounding class, store a ptr to it and create an add fn that adds a timer expecting ptr as first arg
class timer_queue
{
private:
	typedef std::chrono::steady_clock steadyclock;
	typedef std::chrono::time_point<steadyclock> timepoint;
	struct fpair
	{
		timepoint time;
		std::function<void ()> fn;
		// priority compare: higher (later) timestamps are lower priority
		bool operator< (const fpair& other) const { return time > other.time; }
		fpair(timepoint t, std::function<void ()> f) : time(t), fn(f) {}
	};
	std::priority_queue<fpair> q;
public:
	void add(const timepoint& absolute, const std::function<void ()>& f) {
		q.push(fpair(absolute, f));
	}
	void add(size_t seconds, const std::function<void ()>& f) {
		q.push(fpair(steadyclock::now() + std::chrono::seconds(seconds), f));
	}
	void add(const timeval& tv, const std::function<void ()>& f) {
		q.push(fpair(steadyclock::now() + std::chrono::seconds(tv.tv_sec) + std::chrono::microseconds(tv.tv_usec), f));
	}
	// executes all due timers, returns milliseconds until next timer should execute
	ssize_t exec() {
		// steady clock may have more precision than return value, so round up to avoid "0ms" return values that cause busy looping
		timepoint now = steadyclock::now() + std::chrono::milliseconds(1);
		while(!q.empty() && now > q.top().time) {
			// must remove function from queue before executing:
				// else will fandango on core if a new queue entry is added by a function during execution
			std::function<void()> next(std::move(q.top().fn));
			q.pop();
			next();
		}
		if(q.empty())
			return -1;
		// put back the extra millisecond so timers never execute *before* they should
		return std::chrono::duration_cast<std::chrono::milliseconds>(q.top().time - now).count() + 1; 
	}
};

#ifdef WINDOWS
std::string get_env_var(const char *variable_name);
int socketpair(int domain, int type, int protocol, csocket::sock_t fds[]);
// these have to exist (and should not be equal to other families such as AF_INET):
#ifndef AF_LOCAL
#define AF_LOCAL INT_MAX
#endif
#ifndef AF_UNIX
#define AF_UNIX AF_LOCAL
#endif
#endif

// thread-safe queue
template<class T>
class tqueue
{
protected:
	std::mutex m;
	std::queue<T> q;
	// TODO: using csocket here makes common dependent on network, maybe make tqueue and its subclasses their own file
	csocket sd[2]; // socket descriptor pair for poll()/select(), sd[1] ready to read when queue data may be present
	void clear_notify_fd()
	{
		// throw away all the data so the fd won't show read until more is written
		try {
			uint8_t i[100];
			while(sd[1].recv(i, sizeof(i)) == sizeof(i)) {}
		} catch(const e_check_sock_err &e) {
			eout() << "error on tqueue notification file descriptor: " << e;
			throw; // probably nobody catches this, but this should never happpen anyway, so terminate is a sensible outcome
		}
	}
public:
	tqueue() {
		csocket::sock_t socks[2];
		// similar to above, probably nobody catches what this throws, but if this fails then something bad is wrong -> terminate
		check_sock_err(socketpair(AF_LOCAL, SOCK_STREAM, 0, socks), "tqueue(): could not create socket pair");
		sd[0] = csocket(socks[0]);
		sd[1] = csocket(socks[1]);
		sd[0].setopt_nonblock();
		sd[1].setopt_nonblock();
	}
	csocket::sock_t getSD() { return sd[1].fd(); } // socket descriptor notifying of new data (for poll()/select()/etc.)
	template<class E>
	void put(E&& element) {
		std::lock_guard<std::mutex> lk(m);
		q.emplace(std::forward<E>(element));
		// socket is non-blocking and may not send, but only if buffer is already full, in which case no need to send (right?)
		sd[0].send("a", 1);
	}
	void for_each(const std::function<void (T&&)>& f)
	{
		clear_notify_fd();
		std::queue<T> tmpq;
		m.lock();
		std::swap(q, tmpq);
		m.unlock();
		while(!tmpq.empty())
		{
			f(std::move(tmpq.front()));
			tmpq.pop();
		}
	}
};


class pvevent;
class function_tqueue : public tqueue< std::function<void()> >
{
	public:
		void execute() {
			std::queue< std::function<void()> > tmpq;
			clear_notify_fd();
			m.lock();
			std::swap(q, tmpq);
			m.unlock();
			while(!tmpq.empty())
			{
				tmpq.front()();
				tmpq.pop();
			}
		}
		// helper for use with pollvector:
		// TODO: maybe print error on error events (is there any circumstance there should be any?)
		void pv_execute(size_t, const pvevent&, sock_err) { execute(); }
};

// ask a thread with a function_tqueue to pause (for the life of the pause_thread object) so that another thread can play with its bits uncontended
// guaranteed deadlock if you create one against the same thread as the function_tqueue you pass to it
// TODO: originally created this for something else (currently not used at all), but could be good for stop-the-world to do config file re-read
/*class pause_thread
{
public:
	class lock
	{
		friend class pause_thread;
		std::mutex mtx;
		std::condition_variable stop_cond;
		std::condition_variable start_cond;
		bool stopped; // detect spurious wakeups on insane operating systems
		public: lock() : stopped(false) {}
	};
	pause_thread(pause_thread::lock& ptlk, function_tqueue& thread_queue) : pause_lock(ptlk), lifetime_lock(ptlk.mtx) {
		thread_queue.put(std::bind(&pause_thread::stop_wait, this));
		do pause_lock.stop_cond.wait(lifetime_lock); while(!pause_lock.stopped);
	}
	~pause_thread() {
		pause_lock.stopped = false;
		pause_lock.start_cond.notify_one();
	}
private:
	pause_thread::lock& pause_lock;
	std::unique_lock<std::mutex> lifetime_lock;
	void stop_wait() {
		std::unique_lock<std::mutex> stop_lock(pause_lock.mtx);
		pause_lock.stopped = true;
		pause_lock.stop_cond.notify_one();
		do pause_lock.start_cond.wait(stop_lock); while(pause_lock.stopped);
	}
};*/

// (pass object to std::thread)
class worker_thread
{
private:
	function_tqueue work_queue;
	bool running;
public:
	worker_thread() : running(true) {}
	void add(const std::function<void()>& f) { work_queue.put(f); }
	void stop() { work_queue.put([this]() { running = false; }); }
	void operator()() {
		int rv;
		wait_for_read rfd(work_queue.getSD());
		while(running) {
			rv = rfd.wait();
			if(is_sock_err(rv) && sock_err::get_last() != sock_err::eintr)
				throw e_check_sock_err("worker_thread: work queue notify socket", true);
			work_queue.execute();
		}
	}
};



#endif // COMMON_H
