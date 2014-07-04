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

#ifndef TLS_H
#define TLS_H
#include<openssl/ssl.h>
#include<thread>
#include<unordered_map>
#include "../common/err_out.h"
#include "../common/common.h"
#include "crypto.h"
#include "../common/network.h"

// TODO: support session reestablishment

class tls_conn;
typedef std::unique_ptr<tls_conn> dtls_ptr;
class dbuf; 
class dtls_peer
{
public:
	enum PEER_TYPE { HANDSHAKE, VNET };
	virtual PEER_TYPE peer_type() = 0;
	virtual void socket_read_event(dbuf& buf, size_t read_len) = 0;
	virtual void socket_error_occurred() = 0;
	virtual tls_conn& get_conn() = 0;
	virtual void dtls_timeout_occurred() = 0;
	virtual void set_icmp_mtu(uint16_t mtu) = 0;
	virtual void cleanup() = 0;
	virtual ~dtls_peer() {}
};

class dbuf;
class tls_server
{
    private:
        // csocket sock;
        // sockaddrunion server_addr;
		hashkey fingerprint;
		der_pubkey pubkey;
    public:
        tls_server();
		const hashkey& get_hashkey() { return fingerprint; }
		const der_pubkey& get_pubkey() { return pubkey; }

		static void check_keys();
		static digital_signature_signer get_signer();
};

class dtls_peer;
struct tls_thread_tracker;
class tls_conn
{
public:
    // return values for various member functions:
	// TODO: socket error / connection shutdown / tls error should be exceptions, maybe find some way other than return val to signal want read / want write
    enum { TLS_OK = 0, TLS_ERROR = -1, TLS_CONNECTION_SHUTDOWN = -2, TLS_SOCKET_ERROR = -3, TLS_WANT_READ = -4, TLS_WANT_WRITE = -5};
	static dtls_ptr getNewClient(const sockaddrunion& local_su, const sockaddrunion& remote_su, uint8_t* buf, size_t readlen, csocket::sock_t sd);
	tls_conn(const sockaddrunion& local, const sockaddrunion& remote, const hashkey& fingerprnt, csocket::sock_t sd);
	tls_conn(const tls_conn&) = delete; // can't copy these
    ~tls_conn();
    static void tlsInit(); // init TLS library (main() should call this once at startup, before using TLS)
	int do_handshake(uint8_t* readbuf, size_t readlen); // must call until it returns 0 before using read/write
	int do_shutdown(uint8_t* readbuf, size_t readlen); // do clean shutdown (success indicated by TLS_OK, not TLS_CONNECTION_SHUTDOWN)
	int do_handshake();
	int do_shutdown();
	// NOTE: if implementing threads, be sure to call update_thread_tracker whenever a connection is assigned a new thread (or start using a compiler that properly supports thread_local and burn all that cruft)
		// also note that timeout timers are not currently thread safe:
		// if tls_conn is to be used from a thread w/ foreign timer_queue then timers will have to be added using some kind of synchronization not currently present
    int recv(uint8_t* inbuf, size_t inlen, uint8_t* outbuf, size_t outlen);
    int send(const uint8_t* buf, size_t len);
	bool is_client() { return client; }
	bool is_ready() { return state == STATE::READY; }
	bool is_shutdown() { return state == STATE::SHUTDOWN_COMPLETE; }
	bool is_error() { return state == STATE::ERROR_STATE; }
	void set_error() { state = STATE::ERROR_STATE; }
	void set_hashkey_type(uint16_t algo, uint16_t len) { fingerprint = pubkey.get_hashkey(algo, len); } // (this must be called *after* DTLS handshake)
	const hashkey& get_hashkey() { return fingerprint; }
	const der_pubkey& get_pubkey() { return pubkey; }
	const sockaddrunion& get_peer() { return remote_sockaddr; }
	const sockaddrunion& get_local() { return local_sockaddr; }
	in_port_t get_local_port() { return local_sockaddr.get_ip_port(); }
	in_port_t get_remote_port() { return remote_sockaddr.get_ip_port(); }

	void update_thread_tracker(); // call this if the thread owning this tls_conn changes
	bool cert_verified_ok() {
		// this may be unnecessary: does do_handshake() already return TLS_ERROR if verification fails?
		if(ssl==nullptr)
			return false;
		X509* cert = SSL_get_peer_certificate(ssl);
		if(cert != nullptr) { // check that there actually was a certificate (otherwise we get X509_V_OK with no cert)
			X509_free(cert);
			return SSL_get_verify_result(ssl) == X509_V_OK;
		}
		return false;
	}
	static unsigned dtls_overhead_length() {
		// to this the IP overhead must be added, which differs depending on whether IPv4 or IPv6 and whether options are present
			// the best way to get that information is from the inner packet of the "frag needed but DF set" ICMP message
		// this is not actually a constant, it depends on the ciphersuite negotiated, is there any way to get the real number?
		return 8/*UDP header*/ + DTLS1_RT_HEADER_LENGTH + 40/*wild guess*/;
	}
	
	// TODO: could probably pass timer_queue to constructor instead, in practice it never changes [in current implementation]
		// or for that matter use a static one (that may even make more sense when requiring synchronization in the future: static ref to interthread queue to timer queue)
	void set_self(timer_queue* tq, std::weak_ptr<dtls_peer> slf) { timers=tq; self = slf; timeout_scheduled = false; }
    private:
		void update_timeout() {
			timeval tv;
			if(timeout_scheduled==false && state != STATE::ERROR_STATE && DTLSv1_get_timeout(ssl, &tv)) {
				std::weak_ptr<dtls_peer> slf(self);
				timers->add(tv, [slf]() { if(auto ptr = slf.lock()) if(ptr->get_conn().attempt_retransmit()==false) ptr->dtls_timeout_occurred(); });
				timeout_scheduled = true;
			}
		}
		bool attempt_retransmit() {
			if(state==STATE::ERROR_STATE)
				return false;
			timeout_scheduled = false;
			bool rv;
			timeval tv;
			if(!DTLSv1_get_timeout(ssl, &tv)) {
				dout() << "No TLS handshake pending after timeout, not attempting retransmit";
				rv = true; // no timeout required, handshake not pending
				num_retransmission_timeouts = 0;
			} else if(++num_retransmission_timeouts == MAX_RETRANSMISSION_TIMEOUTS) {
				// OpenSSL waits several minutes by default; we may not want to wait that long
				// so if we time out MAX times and a timeout is still ticking, fail
				// TODO: possible better alternative is to let OpenSSL have its fun but trigger retries after more than one retransmit
				rv = false;
			} else {
				dout() << "Attempting TLS handshake retransmit for " << remote_sockaddr << "  " << fingerprint;
				rv = DTLSv1_handle_timeout(ssl) >= 0;
			}
			if(rv)
				{ update_timeout(); }
			else
				{ state = STATE::ERROR_STATE; }
			return rv;
		}
		static SSL_CTX* clientCTX;
        static SSL_CTX *serverCTX;

		static tls_thread_tracker thread_tracker;
		tls_conn** current_pointer; // this points to the *pointer* for the current thread, which gets assigned to 'this' before any OpenSSL operation (for benefit of verify callback)
		std::thread::id current_thread; // the last thread this connection ran on (to tell whether we need to get a new pointer before assigning it)

		SSL* ssl;
		BUF_MEM* rbufmem; // this is the buffer for the read memory BIO
		std::weak_ptr<dtls_peer> self; // this dtls_peer
		timer_queue* timers;
		// peer's public key fingerprint (if initialized, peer-provided cert must hash to it to be accepted)
		hashkey fingerprint; 
		der_pubkey pubkey;
		static bool checkX509fingerprint(X509* check, const hashkey &hk);
		enum class STATE { HANDSHAKE, READY, SHUTDOWN_PENDING, SHUTDOWN_COMPLETE, ERROR_STATE };
		STATE state;
        bool client;
		// timeout_scheduled determines whether a previous call to get_handshake_timeout has not yet been executed by a call to handle_timeout
		// if set, get_handshake_timeout returns false regardless of whether any timeout is active
		// this simplifies the caller code because it can just try to schedule a timeout on every operation and still only have one in flight at any given time
		bool timeout_scheduled;
		sockaddrunion local_sockaddr;
		sockaddrunion remote_sockaddr;
		static const unsigned MAX_RETRANSMISSION_TIMEOUTS = 4;
		unsigned num_retransmission_timeouts;
        static void initCTX(SSL_CTX* ctx);
		static int dtls_verify_callback (X509_STORE_CTX *ctx, void*/*CTX-granularity user defined data (useless)*/); // OpenSSL callback
		tls_conn(const sockaddrunion& local, const sockaddrunion& remote, const hashkey* fp, bool is_client, SSL* ssl_obj, BUF_MEM* bufmem);
		void pre_read(uint8_t* buf, size_t len); // sets buf as read buffer
		void post_read(); // sets read buffer to nullptr/0 bytes (as caller may then deallocate it)
		int recv(uint8_t* outbuf, size_t outlen);
		int handle_openssl_error(int ret, const char* action);
};

#endif // TLS_H
