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

#include<iostream>
#include<unordered_map>
#include<vector>
#include<mutex>
#include<fcntl.h>
#include<unistd.h>
#include<random>
#ifdef WINDOWS
#include<windows.h>
#include<accctrl.h>
#include<aclapi.h>
#include<io.h>
#else
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#endif
#include"tls.h"
#include"configuration.h"
#include"../common/dbuf.h"

/*
	This software can use the OpenSSL library.
	If you redistribute this software together with OpenSSL
	you may also need to abide by the separate terms
	of the OpenSSL license,	see code and license available from openssl.org.
*/
#include<openssl/bio.h>
#include<openssl/err.h>
#include<openssl/rand.h>
#include<openssl/hmac.h>
#include<openssl/sha.h>
#include<openssl/x509v3.h>


/*
    possibly investigate:
    SSL_set_info_callback(ssl, info_cb);
    SSL_set_msg_callback(ssl, msg_cb);

*/

// OpenSSL callbacks
extern "C" {
// OpenSSL locking callbacks, set in tls_conn::tlsInit
static void OpenSSL_locking_callback(int mode, int n, const char * f, int ln)
{
	static std::mutex * OpenSSL_crypto_locks = new std::mutex[CRYPTO_num_locks()];
	try {
		if(mode & CRYPTO_LOCK)
			OpenSSL_crypto_locks[n].lock();
		else
			OpenSSL_crypto_locks[n].unlock();
	} catch(const std::exception &e) {
		eout() << "Caught " << e.what() << " in OpenSSL_locking_callback from " << f << ":" << ln;
		OPENSSL_assert(0);
	} catch(...) {
		// 
		eout() << "Caught unknown exception in OpenSSL_locking_callback from " << f << ":" << ln;
		OPENSSL_assert(0);
	}
}
struct CRYPTO_dynlock_value
{
	std::mutex lock;
};
static struct CRYPTO_dynlock_value * OpenSSL_dynlock_create_callback(const char * f, int ln)
{
	try {
		return new CRYPTO_dynlock_value();
	} catch(...) {
		eout() << "OpenSSL_dynlock_create_callback mutex allocation failure from " << f << ":" << ln;
		OPENSSL_assert(0);
	}
	return nullptr; // (never get here)
}
static void OpenSSL_dynlock_lock_callback(int mode, struct CRYPTO_dynlock_value * lock, const char * f, int ln)
{
	try {
		if(mode & CRYPTO_LOCK)
			lock->lock.lock();
		else
			lock->lock.unlock();
	} catch(const std::exception &e) {
		eout() << "Caught " << e.what() << " in OpenSSL_dynlock_lock_callback from " << f << ":" << ln;
		OPENSSL_assert(0);
	} catch(...) {
		eout() << "Caught unknown exception in OpenSSL_dynlock_lock_callback from " << f << ":" << ln;
		OPENSSL_assert(0);
	}
}
static void OpenSSL_dynlock_destroy_callback(struct CRYPTO_dynlock_value * lock, const char * /*file*/, int /*line*/)
{
	delete lock;
}


/*
cookie: used to prevent DoS in DTLS because otherwise adversary could send spurious (expensive) handshake requests
    (so handshake request must contain cookie and adversary shouldn't have it)

From RFC 4347:

====
 The HelloVerifyRequest message type is hello_verify_request(3).

   The server_version field is defined as in TLS.

   When responding to a HelloVerifyRequest the client MUST use the same
   parameter values (version, random, session_id, cipher_suites,
   compression_method) as it did in the original ClientHello.  The
   server SHOULD use those values to generate its cookie and verify that
   they are correct upon cookie receipt.  The server MUST use the same
   version number in the HelloVerifyRequest that it would use when
   sending a ServerHello.  Upon receipt of the ServerHello, the client
   MUST verify that the server version values match.

Rescorla & Modadugu         Standards Track                    [Page 12]

RFC 4347           Datagram Transport Layer Security          April 2006


   The DTLS server SHOULD generate cookies in such a way that they can
   be verified without retaining any per-client state on the server.
   One technique is to have a randomly generated secret and generate
   cookies as:  Cookie = HMAC(Secret, Client-IP, Client-Parameters)
====
*/
#define COOKIE_SECRET_LEN 32
static uint8_t cookie_secret[COOKIE_SECRET_LEN];
static int generate_sslcookie(SSL *ssl, uint8_t *cookie, unsigned int *cookie_len)
{
	uint8_t client_data_buf[sizeof(in_port_t) + sizeof(in6_addr)];
	unsigned client_data_len;
	sockaddrunion client;
	(void) BIO_ctrl(SSL_get_wbio(ssl), BIO_CTRL_DGRAM_GET_PEER, sizeof(client), &client);
	if(client.ss.ss_family == AF_INET)
	{
		client_data_len = sizeof(in_port_t) + sizeof(in_addr);
		memcpy(client_data_buf, &client.sa.sin_port, sizeof(in_port_t));
		memcpy(client_data_buf + sizeof(in_port_t), &client.sa.sin_addr, sizeof(in_addr));
	} else if(client.ss.ss_family == AF_INET6) {
		client_data_len = sizeof(in_port_t) + sizeof(in6_addr);
		memcpy(client_data_buf, &client.sa6.sin6_port, sizeof(in_port_t));
		memcpy(client_data_buf + sizeof(in_port_t), &client.sa6.sin6_addr, sizeof(in6_addr));
	} else
		return false;
		
	// some old versions of OpenSSL only supported up to 32-byte cookies instead of 256 bytes as DTLS spec requires
	// (see http://www.mail-archive.com/openssl-dev@openssl.org/msg26409.html)
	// so do not use more than 32-byte (256-bit) HMAC for cookie unless we know all users have newer OpenSSL than that
	unsigned char* rv = HMAC(EVP_sha256(), (const void*) cookie_secret, COOKIE_SECRET_LEN, client_data_buf, client_data_len, cookie, cookie_len);
	if(rv == nullptr)
		return false;
	return true;
}

static int verify_sslcookie(SSL *ssl, uint8_t *cookie, unsigned cookie_len)
{
	static const unsigned MAX_COOKIE_LEN = 256; // according to DTLS spec
	uint8_t cookie_shouldbe[MAX_COOKIE_LEN];
	unsigned cookie_len_shouldbe;
	int rv = generate_sslcookie(ssl, cookie_shouldbe, &cookie_len_shouldbe);
	if(rv==false || cookie_len != cookie_len_shouldbe)
		return false;
	return (is_equal(cookie, cookie_shouldbe, cookie_len));
}

static DH *get_dhparams()
{
	FILE* param_file = fopen(snow::conf[snow::DH_PARAMS_FILE].c_str(), "r");
	DH* rv = nullptr;
	if(param_file != nullptr) {
		dout() << "Reading DH params from " << snow::conf[snow::DH_PARAMS_FILE];
		rv = PEM_read_DHparams(param_file, nullptr, nullptr, nullptr);
		fclose(param_file);
		if(rv != nullptr)
			return rv;
	}

	// oops, failed to read from file
	iout() << "Could not access DH params file " << snow::conf[snow::DH_PARAMS_FILE] << ", using SKIP params";
	std::thread th([]() {
		int codes;
		DH* params;
		do {
			iout() << "Background generating new DH params for next time";
			params = DH_generate_parameters(4096, 2, nullptr, nullptr);
		} while(DH_check(params, &codes) == 0);
		FILE* param_outfile = fopen(snow::conf[snow::DH_PARAMS_FILE].c_str(), "w");
		if(param_outfile != nullptr) {
			dout() << "Generated new DH params, writing to file " << snow::conf[snow::DH_PARAMS_FILE];
			PEM_write_DHparams(param_outfile, params);
			fclose(param_outfile);
		} else {
			eout_perr() << "Generated new DH params but could not write to " << snow::conf[snow::DH_PARAMS_FILE];
		}
	});
	th.detach();

	// 4096-bit SKIP DH params: use if no file is available
	static const uint8_t dh4096_p[]={
		0xFE,0xEA,0xD1,0x9D,0xBE,0xAF,0x90,0xF6,0x1C,0xFC,0xA1,0x06,
		0x5D,0x69,0xDB,0x08,0x83,0x9A,0x2A,0x2B,0x6A,0xEF,0x24,0x88,
		0xAB,0xD7,0x53,0x1F,0xBB,0x3E,0x46,0x2E,0x7D,0xCE,0xCE,0xFB,
		0xCE,0xDC,0xBB,0xBD,0xF5,0x65,0x49,0xEE,0x95,0x15,0x30,0x56,
		0x81,0x88,0xC3,0xD9,0x72,0x94,0x16,0x6B,0x6A,0xAB,0xA0,0xAA,
		0x5C,0xC8,0x55,0x5F,0x91,0x25,0x50,0x3A,0x18,0x0E,0x90,0x32,
		0x4C,0x7F,0x39,0xC6,0xA3,0x45,0x2F,0x31,0x42,0xEE,0x72,0xAB,
		0x7D,0xFF,0xC7,0x4C,0x52,0x8D,0xB6,0xDA,0x76,0xD9,0xC6,0x44,
		0xF5,0x5D,0x08,0x3E,0x9C,0xDE,0x74,0xF7,0xE7,0x42,0x41,0x3B,
		0x69,0x47,0x66,0x17,0xD2,0x67,0x0F,0x2B,0xF6,0xD5,0x9F,0xFC,
		0xD7,0xC3,0xBD,0xDE,0xED,0x41,0xE2,0xBD,0x2C,0xCD,0xD9,0xE6,
		0x12,0xF1,0x05,0x6C,0xAB,0x88,0xC4,0x41,0xD7,0xF9,0xBA,0x74,
		0x65,0x1E,0xD1,0xA8,0x4D,0x40,0x7A,0x27,0xD7,0x18,0x95,0xF7,
		0x77,0xAB,0x6C,0x77,0x63,0xCC,0x00,0xE6,0xF1,0xC3,0x0B,0x2F,
		0xE7,0x94,0x46,0x92,0x7E,0x74,0xBC,0x73,0xB8,0x43,0x1B,0x53,
		0x01,0x1A,0xF5,0xAD,0x15,0x15,0xE6,0x3D,0xC1,0xDE,0x83,0xCC,
		0x80,0x2E,0xCE,0x7D,0xFC,0x71,0xFB,0xDF,0x17,0x9F,0x8E,0x41,
		0xD7,0xF1,0xB4,0x3E,0xBA,0x75,0xD5,0xA9,0xC3,0xB1,0x1D,0x4F,
		0x1B,0x0B,0x5A,0x09,0x88,0xA9,0xAA,0xCB,0xCC,0xC1,0x05,0x12,
		0x26,0xDC,0x84,0x10,0xE4,0x16,0x93,0xEC,0x85,0x91,0xE3,0x1E,
		0xE2,0xF5,0xAF,0xDF,0xAE,0xDE,0x12,0x2D,0x12,0x77,0xFC,0x27,
		0x0B,0xE4,0xD2,0x5C,0x11,0x37,0xA5,0x8B,0xE9,0x61,0xEA,0xC9,
		0xF2,0x7D,0x4C,0x71,0xE2,0x39,0x19,0x04,0xDD,0x6A,0xB2,0x7B,
		0xEC,0xE5,0xBD,0x6C,0x64,0xC7,0x9B,0x14,0x6C,0x2D,0x20,0x8C,
		0xD6,0x3A,0x4B,0x74,0xF8,0xDA,0xE6,0x38,0xDB,0xE2,0xC8,0x80,
		0x6B,0xA1,0x07,0x73,0x8A,0x8D,0xF5,0xCF,0xE2,0x14,0xA4,0xB7,
		0x3D,0x03,0xC9,0x12,0x75,0xFB,0xA5,0x72,0x81,0x46,0xCE,0x5F,
		0xEC,0x01,0x77,0x5B,0x74,0x48,0x1A,0xDF,0x86,0xF4,0x85,0x4D,
		0x65,0xF5,0xDA,0x4B,0xB6,0x7F,0x88,0x2A,0x60,0xCE,0x0B,0xCA,
		0x0A,0xCD,0x15,0x7A,0xA3,0x77,0xF1,0x0B,0x09,0x1A,0xD0,0xB5,
		0x68,0x89,0x30,0x39,0xEC,0xA3,0x3C,0xDC,0xB6,0x1B,0xA8,0xC9,
		0xE3,0x2A,0x87,0xA2,0xF5,0xD8,0xB7,0xFD,0x26,0x73,0x4D,0x2F,
		0x09,0x67,0x92,0x35,0x2D,0x70,0xAD,0xE9,0xF4,0xA5,0x1D,0x84,
		0x88,0xBC,0x57,0xD3,0x2A,0x63,0x8E,0x0B,0x14,0xD6,0x69,0x3F,
		0x67,0x76,0xFF,0xFB,0x35,0x5F,0xED,0xF6,0x52,0x20,0x1F,0xA7,
		0x0C,0xB8,0xDB,0x34,0xFB,0x54,0x94,0x90,0x95,0x1A,0x70,0x1E,
		0x04,0xAD,0x49,0xD6,0x71,0xB7,0x4D,0x08,0x9C,0xAA,0x8C,0x0E,
		0x5E,0x83,0x3A,0x21,0x29,0x1D,0x69,0x78,0xF9,0x18,0xF2,0x5D,
		0x5C,0x76,0x9B,0xDB,0xE4,0xBB,0x72,0xA8,0x4A,0x1A,0xFE,0x6A,
		0x0B,0xBA,0xD1,0x8D,0x3E,0xAC,0xC7,0xB4,0x54,0xAF,0x40,0x8D,
		0x4F,0x1C,0xCB,0x23,0xB9,0xAE,0x57,0x6F,0xDA,0xE2,0xD1,0xA6,
		0x8F,0x43,0xD2,0x75,0x74,0x1D,0xB1,0x9E,0xED,0xC3,0xB8,0x1B,
		0x5E,0x56,0x96,0x4F,0x5F,0x8C,0x33,0x63,
		};
	static const uint8_t dh4096_g[]={ 0x02 };

	if ((rv=DH_new()) == nullptr)
		abort();
	rv->p=BN_bin2bn(dh4096_p, sizeof(dh4096_p), nullptr);
	rv->g=BN_bin2bn(dh4096_g, sizeof(dh4096_g), nullptr);
	if ((rv->p == nullptr) || (rv->g == nullptr))
	{
		DH_free(rv);
		abort();
	}
	return rv;
}

} // extern "C"

tls_server::tls_server()
{
	const char* certfile = snow::conf[snow::CERT_FILE].c_str();
	FILE* fp = fopen(certfile, "r");
	X509* x509;
	if(fp != nullptr)
	{
		x509 = PEM_read_X509(fp, nullptr, nullptr, nullptr);
		fclose(fp);
		if(x509 != nullptr) {
			pubkey = der_pubkey(x509);
			fingerprint = pubkey.get_hashkey(md_hash::HASHTYPE::SHA2, 256/8);
			X509_free(x509);
		} else {
			eout() << "Failure to read certificate from " << certfile;
		}
	} else {
		eout_perr() << "Error opening certificate file, hashkey will be invalid: ";
	}
}

digital_signature_signer tls_server::get_signer() {
   return digital_signature_signer(snow::conf[snow::KEY_FILE].c_str(), md_hash::HASHTYPE::SHA2, 256/8);
}






// TODO: this is broken, it creates a file with permissions for CREATOR OWNER but this does not actually work
	// when file is opened by user listed as file owner it comes back with access denied
	// what is necessary is to create a file with permissions for the specific user, not pseudo user "CREATOR OWNER"
#ifdef WINDOWS
int create_owner_permissions_file(const char *filename)
{
	PSID p_creator_sid = nullptr;
    PACL pACL = nullptr;
    EXPLICIT_ACCESS ea;
    SID_IDENTIFIER_AUTHORITY creator_sid = SECURITY_CREATOR_SID_AUTHORITY;

	if(AllocateAndInitializeSid(&creator_sid, 1, SECURITY_CREATOR_OWNER_RID, 0, 0, 0, 0, 0, 0, 0, &p_creator_sid) == false) {
		eout() << "AllocateAndInitializeSid failed for CREATOR_OWNER_RID";
		return -1;
	}

    memset(&ea, 0, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = 0xFFFFFFFF;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance= NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName  = (LPTSTR) p_creator_sid;

	dout() << "SetEntriesInAcl";
    SetEntriesInAcl(1, &ea, nullptr, &pACL);

	dout() << "LocalAlloc PSECURITY_DESCRIPTOR";
    PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR) LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH); 

    InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION);

    SetSecurityDescriptorDacl(pSD, true/*bDaclPresent*/, pACL, false/*not default DACL*/);

	SECURITY_ATTRIBUTES security_attributes;
	security_attributes.nLength = sizeof(SECURITY_ATTRIBUTES); // <- this is so bizarre it seems like it has to be wrong (?)
	security_attributes.lpSecurityDescriptor = pSD;
	security_attributes.bInheritHandle = false;
	
	dout() << "CreateFile " << filename;
	HANDLE filehandle = CreateFileA((LPCTSTR)filename, GENERIC_WRITE, 0/*no sharing*/, &security_attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (p_creator_sid) 
        FreeSid(p_creator_sid);
    if (pACL) 
        LocalFree(pACL);
    if (pSD) 
        LocalFree(pSD);
	if(filehandle == INVALID_HANDLE_VALUE) {
		eout() << "CreateFile produced INVALID_HANDLE_VALUE";
		return -1;
	}
	dout() << "_open_osfhandle";
	return _open_osfhandle((intptr_t)filehandle, 0);
}
#endif

void tls_server::check_keys()
{
	// try to open files for writing with O_EXCL so that it fails if we already have them; if both are opened, create new key and put them in
	dout() << "Checking key file " << snow::conf[snow::KEY_FILE] << ", cert file " << snow::conf[snow::CERT_FILE];

#ifdef WINDOWS
	int key_fd = create_owner_permissions_file(snow::conf[snow::KEY_FILE].c_str());
	dout() << "key_fd: " << key_fd;
#else
	int key_fd = open(snow::conf[snow::KEY_FILE].c_str(), O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
#endif
	if(key_fd==-1) {
	// TODO: on windows it seems to produce "file not found" rather than EEXIST
		if(errno==EEXIST)
			dout() << "Not creating new private key: File exists";
		else
			eout_perr() << "Could not create private key file";
		return;
	}
#ifdef WINDOWS
	int cert_fd = create_owner_permissions_file(snow::conf[snow::CERT_FILE].c_str());
	dout() << "cert_fd: " << key_fd;
#else
	int cert_fd = open(snow::conf[snow::CERT_FILE].c_str(), O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
#endif
	if(cert_fd==-1) {
		eout_perr() << "No private key available, but could not create new certificate file: ";
		close(key_fd);
		return;
	}
	// OK, private key and certificate don't exist, so create them
	
	
	// generate new keys (default 4096 bit RSA):
	RSA* rsa = RSA_generate_key(4096, RSA_F4, nullptr, nullptr);
	EVP_PKEY *private_key = EVP_PKEY_new();
	if(private_key == nullptr)
		throw std::bad_alloc();
	X509* x509 = X509_new();
	if(x509 == nullptr)
		throw std::bad_alloc();
	if(!EVP_PKEY_assign_RSA(private_key, rsa))
		throw std::bad_alloc();
	rsa = nullptr;
	X509_set_version(x509, 2); // sets version to V3 (obviously)
	ASN1_INTEGER_set(X509_get_serialNumber(x509), 0); // set serial number to zero: this will be the 0th certificate signed by the new private key
		// TODO: consider some alternative if we had a private key without a certificate and possibility exists that another cert with that serial number exists
		// (maybe 'key but no cert' is a fatal error)
	X509_gmtime_adj(X509_get_notBefore(x509), 0); 
	X509_gmtime_adj(X509_get_notAfter(x509), (int64_t)3600*24*365*50); // ~50 years in seconds (this will have to be rounded too) 
	X509_set_pubkey(x509, private_key); // get public key from private key	
	
	X509_NAME* subject = X509_get_subject_name(x509);

	// country (is this required? we could stand to do without it)
	// X509_NAME_add_entry_by_txt(subject, "C", MBSTRING_ASC, reinterpret_cast<const uint8_t*>("US"), -1/*len (use strlen)*/, -1/*append*/, 0/*create new*/);
	// canonical name, use hashkey
	der_pubkey pub(x509);
	hashkey hk = pub.get_hashkey(md_hash::SHA2, 32);
	X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, reinterpret_cast<const uint8_t*>(hk.key_string().c_str()), -1/*len (-1 = use strlen)*/, -1/*append*/, 0/*create new*/);
	X509_set_issuer_name(x509, subject); // self-signed (issuer is subject)
	
	// extensions:
	X509V3_CTX ctx;
	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, x509, x509, nullptr, nullptr, 0);
	
	char ca_true[] = "critical,CA:TRUE";
	X509_EXTENSION *ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_basic_constraints, ca_true);
	if(ext == nullptr)
		throw std::bad_alloc();
	X509_add_ext(x509, ext, -1);
	X509_EXTENSION_free(ext);

	char ski_hash[] = "hash";
	ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_key_identifier, ski_hash);
	if(ext == nullptr)
		throw std::bad_alloc();
	X509_add_ext(x509, ext, -1);
	X509_EXTENSION_free(ext);

	// may want "decipherOnly" because usage is also allowed for signatures, and using the same key for both encryption and signatures opens the door to certain attacks
	// "decipherOnly" applies to "keyAgreement" (TODO: it seems to mean 'pubkey deciphers' i.e. digital signatures, but check that it doesn't mean the opposite or something else)
/*	ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_key_identifier, (char*)"critical,keyCertSign,cRLSign,digitalSignature,keyAgreement,decipherOnly");
	if(ext == nullptr) {} // handle error
	X509_add_ext(x509, ext, -1);
	X509_EXTENSION_free(ext);*/
	
	// etc. (more extensions if necessary)
	
	if(!X509_sign(x509, private_key, EVP_sha256()))
		throw std::bad_alloc();
	
	// (write X509/pkey to file)
	iout() << "Generated new key";
	
	FILE* privkey_file = fdopen(key_fd, "w");
	if(privkey_file == nullptr) {
		eout() << "Error opening private key file for writing";
		return;
	}
	// use this instead of PEM_write_PKCS8PrivateKey (per man page)
	PEM_write_PKCS8PrivateKey(privkey_file, private_key, nullptr, nullptr, 0, nullptr, nullptr);
	fclose(privkey_file);
	FILE* cert_file = fdopen(cert_fd, "w");
	if(cert_file == nullptr) {
		eout() << "Error opening certificate key file for writing";
		return;
	}
	PEM_write_X509(cert_file, x509);
	fclose(cert_file);
	
	X509_free(x509);
	EVP_PKEY_free(private_key);
}

SSL_CTX* tls_conn::clientCTX;
SSL_CTX* tls_conn::serverCTX;

void tls_conn::tlsInit()
{
	CRYPTO_malloc_init();
	SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
	CRYPTO_set_locking_callback(&OpenSSL_locking_callback);
	CRYPTO_set_dynlock_create_callback(&OpenSSL_dynlock_create_callback);
	CRYPTO_set_dynlock_lock_callback(&OpenSSL_dynlock_lock_callback);
	CRYPTO_set_dynlock_destroy_callback(&OpenSSL_dynlock_destroy_callback);
	// TODO: CRYPTO_THREADID_set_callback(): default uses address of errno, may need to implement if used on any platform w/o thread-safe errno
		// (though sout_err is broken then too, so maybe such platforms are just not supported)
	std::random_device rd;
	std::random_device::result_type random_data[1024/sizeof(std::random_device::result_type)];
	for(uint32_t i=0; i < sizeof(random_data)/sizeof(std::random_device::result_type); ++i)
		random_data[i] = rd();
	RAND_seed(random_data, sizeof(random_data));
	RAND_bytes(cookie_secret, COOKIE_SECRET_LEN);
	tls_server::check_keys();
    clientCTX = SSL_CTX_new(DTLSv1_client_method());
    initCTX(clientCTX);
    serverCTX = SSL_CTX_new(DTLSv1_server_method());
    initCTX(serverCTX);
	
	SSL_CTX_set_tmp_dh(serverCTX, get_dhparams());

	// TODO: implement session cache (e.g. when local IP addr changes and DTLS connections have to be reestablished)
		// though first check if that's possible: does session have to be from same IP as before? is it possible on a hard disconnect?
		// -> possible alternative for hard disconnects: change out the underlying sockets on both ends (probably req some kind of challenge/response)
    SSL_CTX_set_session_cache_mode(serverCTX, SSL_SESS_CACHE_OFF); 

	// TODO: protocol says server is supposed to supply list of accepted client CAs
		// see also SSL_CTX_set_client_cert_cb (which is the opposite of what we want, but has an informative man page)
			// note that the thing the server is sending to the client is a list of *names* of CAs it accepts.
			// CAs added with SSL_add_client_CA() are only added as names, they are not added to be trusted
			// so create stack of X509_NAME containing the name "snow" which should be on all the certs and use SSL_CTX_set_client_CA_list on server CTX
	
    SSL_CTX_set_cookie_generate_cb(serverCTX, generate_sslcookie);
    SSL_CTX_set_cookie_verify_cb(serverCTX, verify_sslcookie);
}

void tls_conn::initCTX(SSL_CTX* ctx)
{
    SSL_CTX_set_verify_depth (ctx, 0); // does this even do anything given verify callback as implemented?
    SSL_CTX_set_read_ahead(ctx, 1);
	
	// compression must be turned off for DTLS
		// this appears to be a bug in some versions of OpenSSL: they're using zlib with Z_SYNC_FLUSH instead of Z_FULL_FLUSH [apparently this is what TLS spec requires]
		// the latter resets the compression state for each packet, which makes the compression very poor but the alternative is data corruption on packet loss
	// considering how weak state-invalidating DTLS compression inherently is, and given BEAST/CRIME attacks, maybe leaving it off is a good idea anyway
	SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
	
	//certificate stuff goes in here
	// TODO: 'see NOTES section [of man SSL_CTX_use_certificate_file] on why SSL_CTX_use_certificate_chain_file() should be preferred'
	// currently using PEM (SSL_FILETYPE_PEM), might want to use DER (SSL_FILETYPE_ASN1) instead,
		// but can't use SSL_CTX_use_certificate_chain_file with DER (it only allows one cert per file), so additional certs would require SSL_CTX_add_extra_chain_cert
	
	if(!SSL_CTX_use_certificate_file(ctx, snow::conf[snow::CERT_FILE].c_str(), SSL_FILETYPE_PEM)) {
		eout() << "Could not read certificate from " << snow::conf[snow::CERT_FILE];
		throw e_not_found("tls_conn::initCTX CERT_FILE");
	}
	if(!SSL_CTX_use_PrivateKey_file(ctx, snow::conf[snow::KEY_FILE].c_str(), SSL_FILETYPE_PEM)) {
		eout() << "Could not read private key from " << snow::conf[snow::KEY_FILE];
		throw e_not_found("tls_conn::initCTX KEY_FILE");
	}
	if(!SSL_CTX_check_private_key (ctx)) {
		eout() << "Private key " << snow::conf[snow::KEY_FILE] << " invalid or does not match cert " << snow::conf[snow::CERT_FILE];
		throw e_invalid_input("tls_conn::initCTX Private Key");
	}

	// SHA256 as HMAC requires TLS/DTLS 1.2 and current OpenSSL suppports TLS 1.2 but not DTLS 1.2
		// but we can do this and automatically get support for SHA256 whenever the library is updated
	SSL_CTX_set_cipher_list(ctx, "AES+SHA256+kEDH:AES+SHA+kEDH:!aNULL:!eNULL:@STRENGTH");

	// SSL_VERIFY_PEER: (in server case) ask for and (in both cases) check certificate
	// SSL_VERIFY_FAIL_IF_NO_PEER_CERT: protocol makes client certs optional; we want them (mandatory) so fail if not provided
	// SSL_VERIFY_CLIENT_ONCE: in case of SSL_VERIFY_PEER, only ask for a certificate on initial handshake, not on renegotiations
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE, nullptr);
	SSL_CTX_set_cert_verify_callback(ctx, &tls_conn::dtls_verify_callback, nullptr);
}


struct tls_thread_tracker
{
	// this is for the certificate verify callback so that it can know which tls_conn object it's working on (since naturally OpenSSL doesn't pass it)
	// tls_conn sets the relevant pointer prior to calling any OpenSSL function, so based on which thread we're in, we know which object we are
	std::unordered_map<std::thread::id, tls_conn**> thread_map; // maps thread ids to indices into active connections
	std::mutex mutex;
	tls_conn** get_connection()
	{
		std::thread::id id = std::this_thread::get_id();
		std::lock_guard<std::mutex> lk(mutex);
		auto it = thread_map.find(id);
		if(it == thread_map.end())
		{
			// in theory this leaks memory by one pointer per thread created
			// if it actually mattered it could probably be fixed with some kind of hook in the thread termination,
			// but currently all relevant threads effectively live for the life of the process, so there is no relevant thread termination
			// TODO: replace all of this with a 'static thread_local tls_conn::tls_conn* active' when compiler support for 'thread_local' improves
				// also: beware std::async -- lib implementations that context switch async functions within the same thread on a pool will break this
				// (unless each async function is given its own thread ID / thread local storage independent of its pool thread, which it probably isn't)
			
			// allocate *pointer* to tls_conn (to be owned by its associated thread, pointing to thread's active tls_conn)
			tls_conn** newconn = new tls_conn*; 
			*newconn = nullptr;
			thread_map[id] = newconn;
			return newconn;
		}
		return it->second;
	}
};

void tls_conn::update_thread_tracker()
{
	// we have to update the pointer for this thread to point to the current object
	// if this thread is the same thread this object ran on last time, the pointer will also be the same one and we can avoid mutex (only this thread touches that pointer)
	// if not, we have to use a shared object to look up the pointer for the different thread that we're now running on, and then update that
	if(current_thread != std::this_thread::get_id())
	{
		current_thread = std::this_thread::get_id();
		current_pointer = thread_tracker.get_connection();
	}
	*current_pointer = this;
}

// not used?
bool tls_conn::checkX509fingerprint(X509* check, const hashkey &fingerprint) 
{
	if(!md_hash::valid(fingerprint.algo(), fingerprint.size()))
		return false;
	int len;
	uint8_t *buf = nullptr;
	len = i2d_X509(check, &buf);
	if(len < 0)
		return false;
	
	// do hash of buf
	hashkey test_fingerprint(buf, len, fingerprint.algo(), fingerprint.size());
	OPENSSL_free(buf);

	if(fingerprint == test_fingerprint)
			return true;
	return false;
}


int tls_conn::dtls_verify_callback(X509_STORE_CTX* ctx, void*)
{
	// TODO: instead of all this mess with the thread tracker,
		// why not just have the verify callback always return true and then get the cert (somehow?) in do_handshake() and hash it
		// but: advantage of doing it here: if fingerprint is wrong then rejection happens before expensive public key operations
	tls_conn* conn = *thread_tracker.get_connection();
	if(conn==nullptr)
	{
		eout() << "BUG: thread_tracker->get_connection() returned nullptr to dtls_verify_callback";
		ctx->error=X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT;
		return 0;
	}
	
	if(ctx->cert==nullptr)
	{
		eout() << "dtls_verify_callback asked to verify null certificate";
		ctx->error=X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT;
		return 0;
	}
	
	if(conn->pubkey.initialized()) {
		// if pubkey is already known somehow then it must match
		if(conn->pubkey != der_pubkey(ctx->cert)) {
			dout() << "Rejected peer cert (did not match known existing cert)";
			ctx->error = X509_V_ERR_CERT_REJECTED;
			return 0;
		}
	} else  {
		conn->pubkey = der_pubkey(ctx->cert);
	}
	
	if(!conn->pubkey.initialized())
	{
		dout() << "Could not process peer-provided pubkey";
		ctx->error=X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT;
		return 0;
	}

	if(conn->fingerprint.initialized())
	{
		// fingerprint of pubkey that the peer should present in the cert is known, so just check that it hashes correctly
		hashkey fingerprint = conn->pubkey.get_hashkey(conn->fingerprint.algo(), conn->fingerprint.size());
		if(fingerprint == conn->fingerprint)
		{
			dout() << "Accepted peer cert";
			ctx->error = X509_V_OK;
			return 1;
		} else {
			dout() << "Rejected peer cert (hashkey match failed)";
			ctx->error = X509_V_ERR_CERT_REJECTED;
			return 0;
		}
	}
	// else not looking for anyone in particular, so take whatever is provided, but pubkey is recorded so we know who we're talking to
	dout() << "Accepted peer cert (by default)";
	ctx->error = X509_V_OK;
	return 1;
}

tls_thread_tracker tls_conn::thread_tracker; // init static thread tracker

tls_conn::tls_conn(const sockaddrunion& local, const sockaddrunion& remote, const hashkey* fp, bool cl, SSL* ssl_obj, BUF_MEM* bufmem)
	:  ssl(ssl_obj), rbufmem(bufmem), timers(nullptr), state(STATE::HANDSHAKE), client(cl), num_retransmission_timeouts(0)
{
	// don't just call update_thread_tracker here because we have to initialize current_pointer even if uninitialized current_thread is by chance already "right"
	current_thread = std::this_thread::get_id();
	current_pointer = thread_tracker.get_connection();
	*current_pointer = this;

	memcpy(&local_sockaddr, &local, sizeof(sockaddrunion));
	memcpy(&remote_sockaddr, &remote, sizeof(sockaddrunion));

	if(fp != nullptr)
		{ fingerprint = *fp; }
}

tls_conn::tls_conn(const sockaddrunion& local, const sockaddrunion& remote, const hashkey& fp, csocket::sock_t sd)
	: tls_conn(local, remote, &fp, true, SSL_new(clientCTX), nullptr)
{
	// BIO_new_mem_buf() won't accept nullptr buf even if length is zero, so provide alternative nonsense location from which to read no bytes
	BIO* rbio = BIO_new_mem_buf((void*)(1), 0);
	BIO_set_mem_eof_return(rbio, -1);
	BIO* wbio = BIO_new_dgram(sd, BIO_NOCLOSE);
	SSL_set_bio(ssl, rbio, wbio);
	BIO_ctrl(wbio, BIO_CTRL_DGRAM_SET_PEER, 0, &remote_sockaddr.s);
	rbufmem = (BUF_MEM*)rbio->ptr;
}


/* (static) */ dtls_ptr tls_conn::getNewClient(const sockaddrunion& local_su, const sockaddrunion& remote_su, uint8_t* buf, size_t readlen, csocket::sock_t sd)
{
	dout() << "tls_conn::getNewClient with " << readlen << " byte buf, sd " << sd << ", local " << local_su << ", remote " << remote_su;
	BIO* rbio = BIO_new_mem_buf(buf, readlen);
	BIO_set_mem_eof_return(rbio, -1);
	BUF_MEM* bm = (BUF_MEM*)rbio->ptr;
	BIO* wbio = BIO_new_dgram(sd, BIO_NOCLOSE);
	sockaddrunion remote;
	memcpy(&remote, &remote_su, sizeof(sockaddrunion)); // BIO_ctrl takes non-const void* arg (entire concept of BIO_ctrl is defective, someone please destroy)
	BIO_ctrl(wbio, BIO_CTRL_DGRAM_SET_PEER, 0, &remote.s);
	SSL* ssl = SSL_new(serverCTX);
	SSL_set_bio(ssl, rbio, wbio);
	// can't call DTLSv1_listen here because it wrongly assumes rbio is a datagram bio, so the following does the same thing
	// obviously setting the internal state is bad, so fix this later if possible
	SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
	ssl->d1->listen = 1;
	// the way this work is that you call SSL_accept() the first time, it receives client hello w/o cookie and sends request for client to verify cookie, but returns WANT_READ
	// in response we throw away the ssl object and store no state until the client responds by sending client hello again with cookie attached
	// then when we get the client hello with the correct cookie, SSL_accept() returns rv>0 and we proceed
	int rv;
	if ( (rv = SSL_accept(ssl) ) <= 0)
    {
		// (some error)
		switch(SSL_get_error(ssl, rv))
        {
        case SSL_ERROR_ZERO_RETURN: dout() << "DTLSv1_listen: SSL_ZERO_RETURN"; break;
        case SSL_ERROR_WANT_READ: dout() << "DTLSv1_listen: SSL_ERROR_WANT_READ"; break;
        case SSL_ERROR_WANT_WRITE: dout() << "DTLSv1_listen: SSL_ERROR_WANT_WRITE"; break;
        case SSL_ERROR_WANT_CONNECT: dout() << "DTLSv1_listen: SSL_ERROR_WANT_CONNECT"; break;
        case SSL_ERROR_WANT_ACCEPT: dout() << "DTLSv1_listen: SSL_ERROR_WANT_ACCEPT"; break;
        case SSL_ERROR_WANT_X509_LOOKUP: dout() << "DTLSv1_listen: SSL_ERROR_X509_LOOKUP"; break;
        case SSL_ERROR_SYSCALL: dout() << "DTLSv1_listen: SSL_ERROR_SYSCALL"; break;
        case SSL_ERROR_SSL: {
			char errmsg[120];
			ERR_error_string_n(ERR_get_error(), errmsg, sizeof(errmsg));
			dout() << "DTLSv1_listen: SSL_ERROR_SSL: " << errmsg; break;
		}
        default: dout() << "DTLSv1_listen: OTHER SSL ERROR"; break;
        }
		SSL_free(ssl);
		return nullptr;
    }
	if(bm->length != 0)
		dout() << "NOTE: getNewClient clearing non-empty memory BIO";
	bm->data=nullptr;
	bm->length=0;
	bm->max=0;
	return dtls_ptr(new tls_conn(local_su, remote_su, nullptr, false, ssl, bm));
}


int tls_conn::handle_openssl_error(int ret, const char *action)
{
	switch(SSL_get_error(ssl, ret))
	{
	case SSL_ERROR_NONE:
		return TLS_OK;
	case SSL_ERROR_ZERO_RETURN:
		dout() << "Attempted " << action << " on shutdown TLS connection";
		state = STATE::SHUTDOWN_PENDING;
		return TLS_CONNECTION_SHUTDOWN;
	case SSL_ERROR_WANT_READ:
		return TLS_WANT_READ;
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_CONNECT:
	case SSL_ERROR_WANT_ACCEPT:
		return TLS_WANT_WRITE;
	// case SSL_ERROR_WANT_X509_LOOKUP: // should never happen, we don't use SSL_CTX_set_client_cert_cb()
	case SSL_ERROR_SYSCALL: {
		char buf[120];
		ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
		dout_perr() << "Socket error during " << action << ": " << ret << ": ERR:" << buf
					<< ", sock err " << sock_err::get_last() << ", errno ";
		// don't set state to TLS_ERROR, socket errors can be harmless/transitory or fraudulent
		return TLS_SOCKET_ERROR;
	  }
	case SSL_ERROR_SSL: {
		char buf[120];
		ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
		dout() << "DTLS error during " << action << ":" << buf;
		state = STATE::ERROR_STATE;
		return TLS_ERROR;
	  }
	}
	state = STATE::ERROR_STATE;
	dout() << "Unexpected DTLS error during " << action;
	return TLS_ERROR;
}

void tls_conn::pre_read(uint8_t* read_buf, size_t readlen)
{
	rbufmem->data=reinterpret_cast<char*>(read_buf);
	rbufmem->length=readlen;
	rbufmem->max=readlen;
}
void tls_conn::post_read()
{
	if(rbufmem->length != 0)
		dout() << "NOTE: post_read() clearning non-empty mem BIO";
	rbufmem->data=nullptr;
	rbufmem->length=0;
	rbufmem->max=0;
}

int tls_conn::do_handshake(uint8_t* readbuf, size_t readlen)
{
	pre_read(readbuf, readlen);
	int rv = do_handshake();
	post_read();
	return rv;
}
int tls_conn::do_handshake()
{
	*current_pointer = this;
	switch(state)
	{
	case STATE::HANDSHAKE:
		break;
	case STATE::READY:
		return TLS_OK;
	case STATE::ERROR_STATE:
		return TLS_ERROR;
	default:
		return TLS_CONNECTION_SHUTDOWN;
	}
	
    int rv;
    if(client)
        rv = SSL_connect(ssl);
    else
        rv = SSL_accept(ssl);
	if(rv > 0) {
		state = STATE::READY;
		return TLS_OK;
	}
	update_timeout();
	return handle_openssl_error(rv, "handshake");
}

int tls_conn::do_shutdown(uint8_t* readbuf, size_t readlen)
{
	pre_read(readbuf, readlen);
	int rv = do_shutdown();
	post_read();
	return rv;
}
int tls_conn::do_shutdown()
{
	int rv = SSL_shutdown(ssl);
	if(rv == 1) {
		state = STATE::SHUTDOWN_COMPLETE;
		rv = TLS_OK;
	} else if(rv == 0) {
		state = STATE::SHUTDOWN_PENDING;
		dout() << "tls::do_shutdown sent shutdown, waiting for reply";
		rv = TLS_WANT_READ;
	} else {
		switch(SSL_get_error(ssl, rv)) {
	    case SSL_ERROR_WANT_READ:
			dout() << "tls::do_shutdown wants read";
			// if there is application data to be read, SSL_shutdown() can return WANT_READ while OS indicates socket readability
			// so if we get WANT_READ, try reading data to clear the buffer
			do {
				uint8_t buf[8192];
				rv = recv(buf, 8192);
				dout() << "do_shutdown called recv() to clear possible remaining data and got " << rv;
			} while(rv > 0);
			break;
	    case SSL_ERROR_WANT_WRITE:
			dout() << "tls::do_shutdown wants write";
	        rv = TLS_WANT_WRITE;
	    default:
			state = STATE::ERROR_STATE;
			rv = TLS_ERROR;
		}
	}
	update_timeout(); // this may not even do anything
	return rv;
}


int tls_conn::recv(uint8_t* inbuf, size_t inlen, uint8_t* outbuf, size_t outlen)
{
	pre_read(inbuf, inlen);
	int rv = recv(outbuf, outlen);
	post_read();
	return rv;
}

int tls_conn::recv(uint8_t* outbuf, size_t outlen)
{
	*current_pointer = this;
	if(state != STATE::READY && state != STATE::SHUTDOWN_PENDING)
		return TLS_ERROR;
	// TODO: is this necessary or does the same result obtain from SSL_read()?
    if(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)
    {
		state = STATE::SHUTDOWN_PENDING;
		dout() << "Attempted read on shutdown TLS connection";
		return TLS_CONNECTION_SHUTDOWN;
    }
	int rv;
	if((rv = SSL_read(ssl, outbuf, outlen)) <= 0)
		rv = handle_openssl_error(rv, "read");
	update_timeout();
	return rv;
}

int tls_conn::send(const uint8_t* buf, size_t len)
{
	*current_pointer = this;
	if(state != STATE::READY)
		return TLS_ERROR;
    if(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)
    {
		state = STATE::SHUTDOWN_PENDING;
		dout() << "Attempted write on shutdown TLS connection";
        return TLS_CONNECTION_SHUTDOWN;
    }
	int rv = 0;
    if (len > 0) {
        if((rv = SSL_write(ssl, buf, len)) <= 0)
			rv = handle_openssl_error(rv, "write");
    }
	update_timeout();
    return rv;
}

tls_conn::~tls_conn()
{
	// TODO: verify that this frees everything that needs to be freed
	if(ssl != nullptr) {
		SSL_free(ssl);
	}
}

