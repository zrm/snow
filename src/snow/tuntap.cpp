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
#include<windows.h>
#include<winioctl.h>
#include "../common/windows_registry.h"
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <net/if.h>
#ifdef __linux
#include <linux/if_tun.h>
#else
#include <net/if_tun.h>
#endif
#include <sys/ioctl.h>
#include <unistd.h>
#endif
#include<cstdint>
#include "tuntap.h"
#include "configuration.h"
#include "../common/err_out.h"
#include "../common/network.h"


// TODO: windows installer should set TAP-Windows mtu to 1419 by default

#ifdef WINDOWS
#define TAP_WINDOWS_CONTROL_CODE(x) \
	CTL_CODE (FILE_DEVICE_UNKNOWN, x, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TAP_WINDOWS_IOCTL_GET_MAC TAP_WINDOWS_CONTROL_CODE(1)
#define TAP_WINDOWS_IOCTL_GET_MTU TAP_WINDOWS_CONTROL_CODE(3)
#define TAP_WINDOWS_IOCTL_GET_INFO TAP_WINDOWS_CONTROL_CODE(4)
#define TAP_WINDOWS_IOCTL_SET_MEDIA_STATUS TAP_WINDOWS_CONTROL_CODE(6)
#define TAP_WINDOWS_IOCTL_CONFIG_TUN TAP_WINDOWS_CONTROL_CODE(10)

void tuntap::do_read()
{
	do {
		memset(&recv_overlapped, 0, sizeof(recv_overlapped));
		recv_overlapped.hEvent = recv_event;
		// if ReadFile completes synchronously then received_sync is bytes read, otherwise operation is async and received_sync is zero
		if(ReadFile(fd, recv_buf, recv_buf.size(), &received_sync, &recv_overlapped) == FALSE) {
			if(GetLastError() != ERROR_IO_PENDING) {
				throw check_err_exception("tuntap::do_read::ReadFile");
			}
			dout() << "tuntap::do_read proceeding async";
			received_sync = 0; // operation is proceeding asynchronously
			break;
		}
		dout() << "tuntap::do_read got sync bytes " << received_sync;
		if(received_sync != 0)
			break;
		// this should never really happen, if it does (especially repeatedly) then it may be necessary to go to a blocking thread-based implementation for windows
		wout() << "Got synchronous tuntap read of zero bytes, retrying";
		do_read();
	} while(true);
}

void tuntap::do_write(size_t len)
{
	memset(&send_overlapped, 0, sizeof(send_overlapped));
	DWORD bytes_ignored;
	sent_sync = WriteFile(fd, send_buf, len, &bytes_ignored, &send_overlapped);
	if(!sent_sync && GetLastError() != ERROR_IO_PENDING) {
		sent_sync = true; // (an async operation is not pending)
		throw check_err_exception("tuntap::do_write::WriteFile");
	}
}

void tuntap::set_read_ready_cb(const std::function<void()> &cb, size_t default_bufsize)
{
	read_ready_cb = cb;
	// do the first async read here to make data available right away and simplify the code in recv_packet a little
	recv_buf = dbuf(default_bufsize);
	do_read();
}
VOID CALLBACK tuntap::read_event_cb(PVOID param, BOOLEAN /*used for timers, ignored*/)
{
	tuntap* tt = reinterpret_cast<tuntap*>(param);
	tt->read_ready_cb();
}
#endif

// 1419 is the mtu using a 1500 byte ethernet mtu - ipv4 header - udp - dtls with default ciphersuite (I think)
// TODO: read mtu from interface on each OS instead of hard coding 1419 (also have installer set sensible interface MTU)
tuntap::tuntap() : mtu(1419)
{
// TODO: use configuration parameters for registry key names instead of hard coded values
// TODO: package TAP-Windows and change component ID or otherwise figure out how to make it not collide with what OpenVPN uses
	// see comment in %PROGRAMFILES%\TAP-Windows\driver\OemWin2k.inf after installing OpenVPN TAP driver
#ifdef WINDOWS
	sent_sync = true; // no async send in progress
	received_sync = 0;
	memset(&recv_overlapped, 0, sizeof(OVERLAPPED));
	memset(&send_overlapped, 0, sizeof(OVERLAPPED));
	recv_event = CreateEvent(nullptr, FALSE, FALSE, nullptr);
	if(recv_event == INVALID_HANDLE_VALUE)
		throw check_err_exception("CreateEvent failed for tuntap recv_event");
	recv_overlapped.hEvent = recv_event;
	// default callback emits error
	read_ready_cb = []() { eout() << "BUG: tuntap read ready callback called but not set"; };
	if(RegisterWaitForSingleObject(&recv_wait, recv_event, &tuntap::read_event_cb, this, INFINITE, WT_EXECUTEINWAITTHREAD) == FALSE)
		throw check_err_exception("RegisterWaitForSingleObject on tuntap read event");
	adapter_GUID = snow::conf[snow::VIRTUAL_INTERFACE];
	if(adapter_GUID == "auto") {
		try {
			// open registry key for all network adapters
			registry_key adapters(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}", KEY_READ);
			for(auto &it : adapters.subkeys()) {
				try {
					registry_key adapter = it.get(KEY_READ);
					// TODO: change ComponentId from "tap0901" to some other string to remove possible namespace collision with OpenVPN (this has to occur in the driver too)
					if(adapter.values().get_value_string("ComponentId") == "tap0901") {
						adapter_GUID = adapter.values().get_value_string("NetCfgInstanceId");
						break;
					}
				} catch(const registry_exception &re) {
					dout() << "Failed to access registry subkey: " << re;
				}
				
			}
		} catch (const registry_exception &re) {
			eout() << "FATAL: Failed to open network adapters registry key, cannot determine TUN adapter to use: " << re;
			throw;
		}
	}
	dout() << "Adapter GUID: " << adapter_GUID;
	if(adapter_GUID == "auto")
		throw e_not_found("no usable tuntap interface");
	// [at this point GUID is value of NetCfgInstanceId, although there could be more than one interface: check all against something else? (interface name?)]
	// TODO: probably the thing to do is: on install, create a TAP-Windows interface and set its name to 'snow tunnel interface' or so,
		// then set the GUID in the configuration file [or registry setting], and GUI config program can list interfaces by name and allow user to choose
		// then the configured GUID is the interface we use and all of this mess doesn't even need to go here -- it just goes once on install and in the config editor
		// what would then really be useful would be a way (other than changing the ComponentId) to tell other software (e.g. OpenVPN) not to use a particular interface
			// two possible solutions may be to either make sure that snow starts before the other service [somehow] and gets there first,
			// or setting permissions [somehow] so that only snow process has access
	std::string tap_filename("\\\\.\\Global\\");
	tap_filename += adapter_GUID + ".tap";
	fd = CreateFile(tap_filename.c_str(), GENERIC_READ | GENERIC_WRITE, 0/*no shared access*/, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, nullptr);
	if(fd == INVALID_HANDLE_VALUE)
		throw check_err_exception("Failed to open Windows TUN/TAP device");
	// name of specific instance of adapter as shown in control panel can be found in:
		// "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\" + adapter_GUID + "\\Connection"
		// value is "Name"
	
	// set to TUN mode
	// TAP_WIN_IOCTL_CONFIG_TUN takes three args: interface IP addr, network addr and netmask
	if_info ifinfo = get_if_info();
	uint32_t tun_addrs[3] = { ifinfo.if_addr, ifinfo.if_addr & ifinfo.netmask, ifinfo.netmask };
	DWORD rsize;
	if(DeviceIoControl(fd, TAP_WINDOWS_IOCTL_CONFIG_TUN, tun_addrs, sizeof(tun_addrs), tun_addrs, sizeof(tun_addrs), &rsize, nullptr))
		dout() << "TAP-Windows CONFIG_TUN success: " << ss_ipaddr(tun_addrs[0]) << " " << ss_ipaddr(tun_addrs[1]) << " " << ss_ipaddr(tun_addrs[2]);
	else
		eout() << "TAP-Windows CONFIG_TUN FAIL: " << ss_ipaddr(tun_addrs[0]) << " " << ss_ipaddr(tun_addrs[1]) << " " << ss_ipaddr(tun_addrs[2]);

	// set media status as connected
	ULONG connected = TRUE;
	if(DeviceIoControl(fd, TAP_WINDOWS_IOCTL_SET_MEDIA_STATUS, &connected, sizeof(connected), &connected, sizeof(connected), &rsize, nullptr) == FALSE)
		wout() << "Failed to set TAP-Windows media status to connected";
	ULONG ifmtu;
	if(DeviceIoControl(fd, TAP_WINDOWS_IOCTL_GET_MTU, &ifmtu, sizeof(ifmtu), &ifmtu, sizeof(ifmtu), &rsize, nullptr)) {
		dout() << "Read mtu from TAP-Windows interface: " << ifmtu;
		if(ifmtu > MIN_PMTU)
			mtu = ifmtu;
	} else {
		wout() << "Failed to get Tap-Windows MTU, assuming default";
	}
	
	// [flush ARP cache? -> probably unnecessary with tun, but maybe do it anyway? certainly don't want invalid ARP cache entries for pool addrs from before interface startup]
	
	// ... also (may) need to undo whatever configuration (remove addrs from if, routes, etc.) on destruction, CloseHandle on fd, set media status to disconnected, etc.

#else
	check_err((fd = open(snow::conf[snow::CLONE_DEVICE].c_str(), O_RDWR)), "opening tun/tap clone device");
	ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	// check size manually instead of using strncpy: strncpy fails silently and doesn't null terminate if there is insufficient space
	if(snow::conf[snow::VIRTUAL_INTERFACE].size() >= IFNAMSIZ)
		throw check_err_exception("VIRTUAL_INTERFACE name is too long", false);
	strcpy(ifr.ifr_name, snow::conf[snow::VIRTUAL_INTERFACE].c_str());
	check_err(fcntl(fd, F_SETFL, O_NONBLOCK), "setting tuntap socket to non-blocking");
#ifdef __linux
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	check_err(ioctl(fd, TUNSETIFF, (void*) &ifr), "opening tun/tap interface");
#endif
	// note: Mac and BSD require a stupid hack to make tun behave properly because they insist on a single destination address being specified
		// solution is to exclude an address from the address pool and specify it as the destination when configuring the interface
		// then set a route specifying that address as the gateway for the entire snow subnet so OS will send them all to the tun interface
	// TODO: write code to do that programmatically for Mac/BSD
		// existing code seems to work on BSD if you set CLONE_DEVICE to e.g. /dev/tun0 and VIRTUAL_INTERFACE to e.g. tun0 and configure the tun interface manually, e.g.:
		// # ifconfig tun0 create 172.16.0.1 netmask 255.240.0.0 172.31.255.254 mtu 1419
		// # route add -net 172.16.0.0 172.31.255.254 255.240.0.0
		// (note: this must be done each time you start the daemon, when the daemon exits the interface remains but configuration is forgotten; same two commands w/o "create")
		// (note: 'ifconfig tun create' will create next tun# necessary, see if there is any simple way to replicate with API)
		// doing this programmatically requires call to ioctl passing SIOCSIFPHYADDR with in_aliasreq struct as follows:
			// ifra_name = "tun[#]"
			// ifra_addr as local interface addr
			// ifra_dstaddr as fake addr
			// ifra_mask as subnet mask
		// and then adding the route via some call to the BSD routing API
	csocket sock(AF_INET, SOCK_DGRAM); // need ordinary socket for SIOC[GS]*, can't use tun fd
	check_err(ioctl(sock.fd(), SIOCGIFFLAGS, (void*) &ifr), "getting tuntap interface flags");
	if((ifr.ifr_flags & IFF_UP) == 0) {
		dout() << "tuntap interface was not up, trying to bring it up";
		ifr.ifr_flags |= IFF_UP; // make sure interface is up
		check_err(ioctl(sock.fd(), SIOCSIFFLAGS, (void*) &ifr), "setting tuntap interface flags");
	} else {
		dout() << "tuntap interface was up";
	}
	// there are two possible ways of doing this which are both supported: either snow launches as root or with CAP_NET_ADMIN and sets these here,
		// or the interface is persistent and configured ahead of time, in which case only ownership of the interface is necessary
	// so what we do is check that everything is configured correctly and try to fix it if it isn't
	// that way everything is fine as long as the interface is correctly preconfigured -or- it isn't but we have rights to fix it
	in_addr addr, netmask;
	inet_pton(AF_INET, snow::conf[snow::NATPOOL_NETWORK].c_str(), &addr.s_addr);
	addr.s_addr = htonl(ntohl(addr.s_addr) + 1);
	netmask.s_addr = ~htonl((1 << (32 - snow::conf[snow::NATPOOL_NETMASK_BITS])) - 1);
	ifr.ifr_addr.sa_family = AF_INET;
	// EADDRNOTAVAIL is returned if no address is assigned which just means we have to assign the address, so then ifr_addr will be zero and not match addr
	int rv = ioctl(sock.fd(), SIOCGIFADDR, &ifr);
	if(rv < 0 && errno != EADDRNOTAVAIL)
		throw check_err_exception("getting tun/tap interface IP address");
	sockaddrunion su;
	su.s = ifr.ifr_addr;
	dout() << "Got tuntap ifaddr " << ss_ipaddr(su.sa.sin_addr.s_addr);
	if(su.sa.sin_addr.s_addr != addr.s_addr) {
		dout() << "Virtual interface IP addr was " << ss_ipaddr(su.sa.sin_addr.s_addr) << ", should be " << ss_ipaddr(addr.s_addr) << ", trying to fix";
		su.sa.sin_addr = addr;
		ifr.ifr_addr = su.s;
		check_err(ioctl(sock.fd(), SIOCSIFADDR, &ifr), "setting tun/tap interface IP address");
	}
	check_err(ioctl(sock.fd(), SIOCGIFNETMASK, &ifr), "getting tun/tap interface netmask");
	su.s = ifr.ifr_addr;
	dout() << "Got tuntap netmask " << ss_ipaddr(su.sa.sin_addr.s_addr);
	if(su.sa.sin_addr.s_addr != netmask.s_addr) {
		dout() << "Virtual interface netmask was " << ss_ipaddr(su.sa.sin_addr.s_addr) << ", should be " << ss_ipaddr(netmask.s_addr) << ", trying to fix";
		su.sa.sin_addr = netmask;
		ifr.ifr_addr = su.s;
		check_err(ioctl(sock.fd(),  SIOCSIFNETMASK, &ifr), "setting tun/tap interface netmask");
	}
	mtu = snow::conf[snow::VIRTUAL_INTERFACE_MTU];
	check_err(ioctl(sock.fd(), SIOCGIFMTU, (void*) &ifr), "getting tun/tap interface MTU");
	dout() << "Existing tuntap interface MTU: " << ifr.ifr_mtu;
	if(ifr.ifr_mtu <  MIN_PMTU || mtu != static_cast<unsigned>(ifr.ifr_mtu)) {
		dout() << "Virtual interface mtu was " << ifr.ifr_mtu << ", should be " << mtu << ", trying to fix";
		ifr.ifr_mtu = mtu;
		check_err(ioctl(sock.fd(), SIOCSIFMTU, (void*) &ifr), "setting tun/tap interface MTU");
	}
	iout() << "Virtual interface configured with network " << ss_ipaddr(addr.s_addr&netmask.s_addr) << " netmask " << ss_ipaddr(netmask.s_addr) <<  " address " << ss_ipaddr(addr.s_addr) << " MTU " << mtu;	
#endif
}

tuntap::if_info tuntap::get_if_info()
{
#ifdef WINDOWS
	if_info rv;
	std::string interface_key = "SYSTEM\\CurrentControlSet\\services\\Tcpip\\Parameters\\Interfaces\\" + adapter_GUID;
	std::vector<std::string> addr, mask;
	try {
		registry_key adapter(HKEY_LOCAL_MACHINE, interface_key.c_str(), KEY_READ);
		addr = adapter.values().get_value_multi_string("IPAddress"), mask = adapter.values().get_value_multi_string("SubnetMask");
	} catch (const registry_exception &re) {
		eout() << "Failed to open registry key for TUN/TAP adapter (HKLM\\" << interface_key << "), cannot determine TUN/TAP adapter IP addr/netmask: " << re;
		throw;
	}
	if(addr.size() != mask.size())
		throw e_invalid_input("Invalid registry data: Number of IP addresses on virtual interface did not match number of subnet masks");
	if(addr.size() == 0)
		throw e_not_found("No IP address assigned to virtual interface");
	if(addr.size() > 1)
		wout() << "Support for multiple IP addresses on virtual interface not implement, only the first address will be used: " << addr.front();
	if(inet_pton(AF_INET, addr.front().c_str(), &rv.if_addr) <= 0)
		throw check_err_exception("Could not convert virtual interface address string to IP address");
	if(inet_pton(AF_INET, mask.front().c_str(), &rv.netmask) <= 0)
	throw check_err_exception("Could not convert virtual interface netmask string to IP address");
	return rv;
#else
	if_info rv;
	csocket sock(AF_INET, SOCK_DGRAM); // need AF_INET socket for SIOCGIFADDR/SIOCGIFNETMASK
	ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	if(snow::conf[snow::VIRTUAL_INTERFACE].size() >= IFNAMSIZ)
		throw e_invalid_input("Virtual interface name length is too long");
    strcpy(ifr.ifr_name, snow::conf[snow::VIRTUAL_INTERFACE].c_str());
	ifr.ifr_addr.sa_family = AF_INET; // get IPv4 addr
	check_err(ioctl(sock.fd(), SIOCGIFADDR, &ifr), "getting tun/tap interface IP address");
	sockaddrunion tmp;
	tmp.s = ifr.ifr_addr;
	rv.if_addr = tmp.sa.sin_addr.s_addr;
	check_err(ioctl(sock.fd(), SIOCGIFNETMASK, &ifr), "getting tun/tap interfacet netmask");
	tmp.s = ifr.ifr_addr;
	rv.netmask = tmp.sa.sin_addr.s_addr;
	return rv;
#endif
}

size_t tuntap::recv_packet(dbuf &buf)
{
#ifdef WINDOWS
	// interesting possible trouble: if async read fails then obviously want to retry, but then how to avoid busy looping?
		// -> maybe do the retry but also then throw exception to indicate the failure
		// this means that before throw the buffers have to be swapped back so that non-error previous read is not lost
	if(received_sync > 0) {
		DWORD bytes_read = received_sync;
		std::swap(buf, recv_buf);
		if(buf.size() < recv_buf.size())
			buf.resize(recv_buf.size());
		do_read();
		return bytes_read;
	} else if(HasOverlappedIoCompleted(&recv_overlapped)) {
		DWORD bytes_read;
		if(GetOverlappedResult(fd, &recv_overlapped, &bytes_read, FALSE) == FALSE) {
#warning fixme GetLastError, throw exception
			// GetLastError should not be ERROR_IO_INCOMPLETE because otherwise HasOverlappedIoCompleted should have been false
		}
		std::swap(buf, recv_buf);
		if(buf.size() < recv_buf.size())
			buf.resize(recv_buf.size());
		do_read();
		return bytes_read;
	}
	// else async read is still in progress, no data to return yet
	return 0;
#else
	ssize_t nread = read(fd, buf, buf.size());
	if(nread >= 0)
		return nread;
	if(errno == EWOULDBLOCK || errno == EAGAIN)
		return 0;
	throw e_check_sock_err("read from tuntap failed", true);
#endif	
}

bool tuntap::send_packet(dbuf &buf, size_t len)
{
#ifdef WINDOWS
	if(sent_sync || HasOverlappedIoCompleted(&send_overlapped)) {
		std::swap(buf, send_buf);
		if(buf.size() < send_buf.size())
			buf.resize(send_buf.size());
		do_write(len);
		return true;
	}
	// else previous async send has not completed
	return false; 
#else
	ssize_t nwritten = write(fd, buf, len);
	if(nwritten > 0)
		return true;
	if(errno == EWOULDBLOCK || errno == EAGAIN)
		return false;
	throw e_check_sock_err("write to tuntap failed", true);
#endif
}

tuntap::~tuntap()
{
#ifdef WINDOWS
	// TODO: call UnregisterWait in a sensible way if recv_wait is not INVALID_HANDLE_VALUE
	// probably ought to cancel the async io operation(s) as well
	if(recv_event != INVALID_HANDLE_VALUE)
		if(CloseHandle(recv_event) == false)
			dout_perr() << "Failed to close recv_event handle in tuntap destructor:";
	if(fd != INVALID_HANDLE_VALUE)
		if(CloseHandle(fd) == false)
			dout_perr() << "Failed to close tuntap fd handle in tuntap destructor:";
#endif
	
}
