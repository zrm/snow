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

#ifdef WINDOWS
#include<Windows.h>
#else
#include<syslog.h>
#endif
#include"../common/err_out.h"

#ifdef WINDOWS
std::string get_windows_errorstr(int e)
{
	// this is just using the ANSI version, windows unicode support is ancient and brain damaged, but may have to deal with it eventually
	char *s = nullptr;
	std::string str;
	unsigned rv = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, 
							  nullptr, e, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&s, 0, nullptr);
	if(rv > 0) {
		str = std::string(s, rv);
		LocalFree(s);			
	} else {
		std::stringstream ss;
		ss << "[error retreiving (WSA)GetLastError string for ";
		ss << e;
		ss << "]";
		str = ss.str();
	}
	return str;
}
#endif
#ifdef WINSOCK
bool is_sock_err(int rv)
{
	return rv == SOCKET_ERROR;
}
bool is_invalid_sock(SOCKET sock)
{
	return sock == INVALID_SOCKET:
}
e_check_sock_err::e_check_sock_err(const std::string &s, bool print_errno) : check_err_exception(s, false) { err = WSAGetLastError(); }
void e_check_sock_err::print(std::ostream &out) const
{
	out << err_string;
	if(err) {
		out << ":[WSA" << err << "]: " << get_windows_errorstr(err);
	} else {
		out << ":[WSA no errno]";
	}
}
#endif

#ifdef WINDOWS
// TODO: don't hard code this (really don't use this at all, use event log)
std::ofstream debugfile("c:/snow_debug_output.txt");
#endif


xout_static::xout_static() : use_syslog(false) {
	lvl[ static_cast<unsigned>(ERRLVL::L_ERROR) ]=(" ERROR : ");
	lvl[static_cast<unsigned>(ERRLVL::L_WARNING)]=("WARNING: ");
	lvl[ static_cast<unsigned>(ERRLVL::L_INFO)  ]=(" INFO  : ");
	lvl[ static_cast<unsigned>(ERRLVL::L_DEBUG) ]=(" DEBUG : ");
#ifndef WINDOWS
	prio[ static_cast<unsigned>(ERRLVL::L_ERROR) ]=LOG_ERR;
	prio[static_cast<unsigned>(ERRLVL::L_WARNING)]=LOG_WARNING;
	prio[ static_cast<unsigned>(ERRLVL::L_INFO)  ]=LOG_INFO;
	prio[ static_cast<unsigned>(ERRLVL::L_DEBUG) ]=LOG_DEBUG;
#endif
}

void xout_static::syslog(unsigned level)
{
#ifdef WINDOWS
	// TODO: use windows event log
	debugfile << ss.str();
#else
	   ::syslog(prio[level], "%s", ss.str().c_str());
#endif
	   ss.str("");
	   ss.clear();
}

void xout_static::enable_syslog(const char* daemon_name)
{
	xout_static::static_block.use_syslog = true;
#ifndef WINDOWS
	openlog(daemon_name, LOG_CONS /* | LOG_PID */, LOG_DAEMON);
#endif
}

xout_static xout_static::static_block;

