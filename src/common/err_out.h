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

#ifndef ERR_OUT_H
#define ERR_OUT_H
#include<iostream>
#include<fstream>
#include<mutex>
#include<cstring>
#include<sstream>

// portable thread-safe strerror
	// strerror() is not thread safe because it writes errno to global char buf when invalid
	// strerror_r() is not portable, GNU version differs from XSI/POSIX version and doesn't exist on windows at all
// this doesn't provide the actual errno for invalid values, but if the caller wants that they can just print it themselves
inline const char * strerror_rp(int errnum) {
#ifdef WINDOWS
	if(errnum < _sys_nerr)
		return _sys_errlist[errnum];
#else
	if(errnum < sys_nerr)
		return sys_errlist[errnum];
#endif
	static const char invalid_errno[] = "Invalid errno";
	return invalid_errno;
}

enum class ERRLVL { L_ERROR, L_WARNING, L_INFO, L_DEBUG };

template<ERRLVL> class xout;
// xout_static: some static data common to every xout instantiation regardless of errlvl (excluding DEBUG NOP specialization)
class xout_static
{
	template<ERRLVL E> friend class xout;
	// recursive mutex is much safer here in case some ostream fn calls xout itself (or e.g. throws exception that prints) and would otherwise deadlock
	std::recursive_mutex output_mutex; 
	std::string lvl[4]; // map ERRLVL to string
	int prio[4]; // map ERRLVL to syslog priority
	std::stringstream ss;
	bool use_syslog;
	xout_static();
	void syslog(unsigned level);
	static xout_static static_block;
public:
	static void enable_syslog(const char* daemon_name);
};



// xout: thread synchronized output, use like this:
	// iout() << "something that should be printed at info errlvl: " << foo.bar << ", thing to print after";
template<ERRLVL E = ERRLVL::L_DEBUG>
class xout
{
	typedef std::basic_ostream<char>&(*ostream_type)(std::basic_ostream<char>&);
public:
	static const ostream_type& clean(const ostream_type& rv) { return rv; } // resolve type ambiguities
	xout() {
		xout_static::static_block.output_mutex.lock();
		if(!xout_static::static_block.use_syslog)
			*this << xout_static::static_block.lvl[static_cast<unsigned>(E)];
	}
	~xout() {
		*this << clean(std::endl);
		if(xout_static::static_block.ss.tellp() != 0)
			xout_static::static_block.syslog(static_cast<unsigned>(E));
		xout_static::static_block.output_mutex.unlock();
	}
	template<class T>
	const xout<E>& operator<<(T&&) const;
};


template<ERRLVL E>
class xout_perr : public xout<E>
{
public:
	~xout_perr() { *this << ": " << strerror_rp(errno); }
};

typedef xout<ERRLVL::L_DEBUG> dout;
typedef xout<ERRLVL::L_WARNING> wout;
typedef xout<ERRLVL::L_INFO> iout;
typedef xout<ERRLVL::L_ERROR> eout;
typedef xout_perr<ERRLVL::L_DEBUG> dout_perr;
typedef xout_perr<ERRLVL::L_WARNING> wout_perr;
typedef xout_perr<ERRLVL::L_INFO> iout_perr;
typedef xout_perr<ERRLVL::L_ERROR> eout_perr;

#ifdef WINDOWS
extern std::ofstream debugfile;
std::string get_windows_errorstr(int e);
#endif

// specialize to allow (compile-time) difference in output based on errlvl, e.g. disable debug output or use cerr for error
template<ERRLVL E>
template<class T>
inline const xout<E>& xout<E>::operator<<(T&& t) const
{
	if(xout_static::static_block.use_syslog)
		xout_static::static_block.ss << t;
	else
		std::cout << t;
	return *this;
}

template<>
template<class T>
inline const xout<ERRLVL::L_ERROR>& xout<ERRLVL::L_ERROR>::operator<<(T&& t) const
{
	if(xout_static::static_block.use_syslog)
		xout_static::static_block.ss << t;
	else
		std::cerr << t;
	return *this;
}

#ifndef ERR_OUT_DEBUG
// NOP specialization for debug prints in release version
template<>
class xout<ERRLVL::L_DEBUG>
{
public:
	template<class T>
	inline const xout<ERRLVL::L_DEBUG>& operator<<(T&&) const { return *this; }
};
template<> class xout_perr<ERRLVL::L_DEBUG> : public xout<ERRLVL::L_DEBUG> {};
#endif

class e_exception : public std::exception
{
protected:
	std::string err_string;
	e_exception(const std::string s) : err_string(s) {}
	e_exception(const std::string &a, const std::string &b) : err_string(a + ": " + b) {}
public:
	virtual const std::string& errstr() const noexcept { return err_string; }
	virtual const char* what() const noexcept { return errstr().c_str(); }
	virtual void print(std::ostream &out) const { out << errstr(); }
};


inline std::ostream &operator<<(std::ostream &out, const e_exception &e)
{
	e.print(out);
	return out;
}

struct e_not_found : public e_exception
{
	e_not_found() : e_exception("not found") {}
	e_not_found(const std::string s) : e_exception(s, "not found") {}
};
struct e_invalid_input : public e_exception
{
	e_invalid_input() : e_exception("invalid input") {}
	e_invalid_input(const std::string s) : e_exception(s, "invalid input") {}
};
struct e_resource_exhaustion: public e_exception
{
	e_resource_exhaustion() : e_exception("resource exhaustion") {}
	e_resource_exhaustion(const std::string s) : e_exception(s, "resource exhaustion") {}
};
struct e_slow_down : public e_exception
{
	e_slow_down() : e_exception("too many retries too fast") {}
	e_slow_down(const std::string s) : e_exception(s, "too many retries too fast") {}
};
struct e_timeout : public e_exception
{
	e_timeout() : e_exception("timeout") {}
	e_timeout(const std::string s) : e_exception(s, "timeout") {}
};

// check_err_exception: a function (generally a C function) returned some error; errno/GetLastError()/sock_err::get_last()/etc may provide details
class check_err_exception : public e_exception
{
protected:
	int err;
public:
	check_err_exception(const std::string &s, bool print_errno = true) : e_exception(s), err(print_errno ? errno : 0) {}
	virtual void print(std::ostream &out) const {
		out << err_string;
		if(err) {
			out << ":" << err << ": " << strerror_rp(err);
		}
	}
};

inline void check_err(int err, const char *msg, bool perr = true)
{
		if(err < 0)
			throw check_err_exception(msg, perr);
}

// this is for winsock: it uses errors differently (WSAGetLastError rather than errno) so sock errors get a separate exception
// for platforms other than windows it is effectively equivalent to check_err_exception and no separate treatment would be required
// and callers should be able to catch as reference to parent without any real need for special treatment
// see also sock_err in network.h which wraps the two sets of error constants in a class to avoid ifdefs everywhere else
#ifdef WINSOCK
class e_check_sock_err : public check_err_exception
{
public:
	e_check_sock_err(const std::string &s, bool print_errno = true);
	virtual void print(std::ostream &out) const;
};
bool is_sock_err(int rv);
bool is_invalid_sock(SOCKET sock);
#else
class e_check_sock_err : public check_err_exception
{
public:
	e_check_sock_err(const std::string &s, bool print_errno) : check_err_exception(s, print_errno) {}
};
inline bool is_sock_err(int rv) { return rv < 0; }
inline bool is_invalid_sock(int sock) { return sock < 0; }
#endif
inline void check_sock_err(int err, const char *msg, bool perr = true)
{
	if(is_sock_err(err))
		throw e_check_sock_err(msg, perr);
}


// debugging tool: make this a member of something and it prints on construction, destruction and calls to default copy and move constructors and assignment operators
struct object_lifetime
{
	std::string str;
	object_lifetime() { dout() << "object_lifetime()"; }
	object_lifetime(const std::string &s) : str(s) { dout() << str << " object_lifetime(string)"; }
	object_lifetime(const object_lifetime &o) : str(o.str) { dout() << str << " object_lifetime(const object_lifetime&)"; }
	object_lifetime(object_lifetime &&o) : str(o.str) { dout() << str << " object_lifetime(object_lifetime&&)"; }
	object_lifetime &operator=(const object_lifetime &o) { dout() << str << " object_lifetime = (const &) -> " << o.str; str = o.str; return *this; }
	object_lifetime &operator=(object_lifetime &&o) { dout() << str << " object_lifetime = (&&) -> " << o.str; str = o.str; return *this; }
	~object_lifetime() { dout() << str << " ~object_lifetime()"; }
};

#endif // ERR_OUT_H
