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

#include "../common/pollvector.h"
#include "../common/err_out.h"

// static pvevents: count as powers of 2 so that | ^ & work nicely
// use implementation defined values for easy mapping where useful
const pvevent pvevent::none(0);
#if defined(PV_USE_EPOLL)
const pvevent pvevent::read(EPOLLIN);
const pvevent pvevent::write(EPOLLOUT);
const pvevent pvevent::error(EPOLLERR | EPOLLHUP);
#elif defined(PV_USE_KQUEUE)
// TODO: does kqueue use xor filter values too or do we have to do this?
const pvevent pvevent::read(1);
const pvevent pvevent::write(2);
const pvevent pvevent::error(4);
#elif defined(WINSOCK)
const pvevent pvevent::read(FD_READ | FD_ACCEPT | FD_CLOSE);
const pvevent pvevent::write(FD_WRITE | FD_CONNECT);
const pvevent pvevent::error(~(FD_READ | FD_ACCEPT | FD_WRITE | FD_CONNECT | FD_CLOSE));
#else
// poll()
const pvevent pvevent::read(POLLIN);
const pvevent pvevent::write(POLLOUT);
const pvevent pvevent::error(POLLERR | POLLHUP);
#endif

void print_poll_error(const pollfd& p)
{
#ifndef WINSOCK
	if(p.revents & POLLIN) dout() << "poll() revent was POLLIN";
	if(p.revents & POLLOUT) dout() << "poll() revent was POLLOUT";
	if(p.revents & POLLPRI) dout() << "poll() revent was POLLPRI";
	if(p.revents & POLLERR) dout() << "poll() revent was POLLERR";
	if(p.revents & POLLHUP) dout() << "poll() revent was POLLHUP";
	if(p.revents & POLLNVAL) dout() << "poll() revent was POLLNVAL";
#ifdef __linux
	if(p.revents & POLLRDHUP) dout() << "poll() revent was POLLRDHUP";
#endif
#endif
}

#ifdef PV_USE_EPOLL
void print_epoll_error(uint32_t events)
{
	if(events & EPOLLIN) dout() << "event was EPOLLIN";
	if(events & EPOLLOUT) dout() << "event was EPOLLOUT";
	if(events & EPOLLRDHUP) dout() << "event was EPOLLRDHUP";
	if(events & EPOLLHUP) dout() << "event was EPOLLHUP";
	if(events & EPOLLPRI) dout() << "event was EPOLLPRI";
	if(events & EPOLLERR) dout() << "event was EPOLLERR";
	if(events & EPOLLET) dout() << "event was EPOLLET";
	if(events & EPOLLONESHOT) dout() << "event was EPOLLONESHOT";
}
#endif
