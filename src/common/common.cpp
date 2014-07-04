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

#include"common.h"

#ifdef WINDOWS
#include"network.h"
int socketpair(int domain, int type, int /*protocol, ignored*/, csocket::sock_t fds[])
{
	if(domain != AF_LOCAL) {
		// this is generally the only one supported by the real socketpair()
		WSASetLastError(WSAEAFNOSUPPORT);
		return -1;
	}
	if(type != SOCK_DGRAM && type != SOCK_STREAM) {
		WSASetLastError(WSAESOCKTNOSUPPORT);
		return -1;
	}
	try {
		uint32_t localhost_addr = htonl(0x7f000001); // 127.0.0.1
		sockaddrunion su;
		memset(&su, 0, sizeof(su));
		su.sa.sin_addr.s_addr = localhost_addr;
		su.sa.sin_family = AF_INET;
		su.sa.sin_port = 0;
		if(type == SOCK_STREAM) {
			csocket listen_sock(AF_INET, SOCK_STREAM);
			listen_sock.bind(su);
			listen_sock.getsockname(su);
			listen_sock.listen();
			csocket a(AF_INET, SOCK_STREAM);
			a.connect(su);
			a.getsockname(su);
			sockaddrunion a_peer;
			csocket b = listen_sock.accept(a_peer);
			while(a_peer.sa.sin_addr.s_addr != localhost_addr || a_peer.sa.sin_port != su.sa.sin_port)
				b = listen_sock.accept(a_peer);
			fds[0] = a.release_fd();
			fds[1] = b.release_fd();
		} else {
			csocket a(AF_INET, SOCK_DGRAM), b(AF_INET, SOCK_DGRAM);
			a.bind(su);
			b.bind(su);
			a.getsockname(su);
			b.connect(su);
			b.getsockname(su);
			a.connect(su);
			fds[0] = a.release_fd();
			fds[1] = b.release_fd();
		}
	} catch(const check_err_exception &e) {
		dout() << "windows socketpair() implementation got " << e;
		// the real socketpair() doesn't throw,
		// so do this and caller can check sock_err::get_last() to get real error as usual
		return -1;
	}
	return 0;
}

std::string get_env_var(const char *variable_name)
{
	char var[32767]; // max windows environment variable length
	DWORD len = GetEnvironmentVariable(variable_name, var, 32767);
	if(len > 32767 || len == 0)
		return "";
	return var;
}


#endif
