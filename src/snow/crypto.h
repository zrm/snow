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

#ifndef CRYPTO_H
#define CRYPTO_H
#include<cstdint>
#include<algorithm>

#include<openssl/x509.h>
#include<openssl/sha.h>
#include<openssl/whrlpool.h>
#include<openssl/pem.h>

#include"../common/err_out.h"
#include"../common/common.h" // is_equal, base32

class md_hash
{
	friend class digital_signature_signer;
	friend class digital_signature_verify;
public:
	// TODO: maybe add support for some more hash algorithms (e.g. SHA3)
	enum HASHTYPE { DATA, SHA2, SHA3, WHIRL_POOL,	/*not an algorithm:*/ MAX_ALGO };
private:
	EVP_MD_CTX* mdctx;
	unsigned hashlen; // needs to be unsigned int because EVP_DigestFinal_ex wants ptr to it
	static const EVP_MD* evp_md(uint16_t hash_algo, uint16_t hashlen);
public:
	static bool valid(uint16_t hash_algo, uint16_t hashlen) { return evp_md(hash_algo, hashlen) != nullptr; }
	bool valid() { return mdctx != nullptr; }
	md_hash(uint16_t hash_algo, uint16_t hash_len);
	~md_hash() { if(mdctx != nullptr) EVP_MD_CTX_destroy(mdctx); }
	void update(uint8_t* data, size_t len) { EVP_DigestUpdate(mdctx, data, len); }
	// writes message digest to "md" which must provide at least hashlen space (as provided to constructor)
	void write_final(uint8_t* md) { EVP_DigestFinal_ex(mdctx, md, &hashlen); }
	static void digest(uint16_t hash_algo, uint16_t hashlen, const uint8_t* data, size_t data_len, uint8_t* md);
};

class hashkey
{
	uint8_t *key;
	uint16_t hashalgo; // host byte order, see md_hash::HASHTYPE
	uint16_t keysize; // host byte order, size of key[]
public:
	uint16_t algo() const { return hashalgo; }
	uint16_t size() const { return keysize; }
	const uint8_t* get_raw() const { return key; }
	hashkey() : key(nullptr), hashalgo(md_hash::HASHTYPE::DATA), keysize(0) {}
	hashkey(const void* k, uint16_t h_algo, uint16_t sz) : key(new uint8_t[sz]), hashalgo(h_algo), keysize(sz)  { memcpy(key, k, sz); }
	hashkey(const uint8_t* data, size_t datalen, uint16_t h_algo, uint16_t hashlen);

	hashkey(const hashkey& h) : key((h.key!=nullptr) ? new uint8_t[h.keysize] : nullptr), hashalgo(h.hashalgo), keysize(h.keysize) { memcpy(key, h.key, keysize); }
	hashkey(hashkey&& h) : key(h.key), hashalgo(h.hashalgo), keysize(h.keysize) { h.key=nullptr; }
	hashkey& operator=(const hashkey& h);
	hashkey& operator=(hashkey&& h);
	~hashkey() { if(key!=nullptr) delete[] key; }
	bool operator==(const hashkey& h) const { return keysize==h.keysize && is_equal(key, h.key, keysize) && hashalgo==h.hashalgo; }
	bool operator!=(const hashkey& h) const { return !(*this == h); }
	bool operator<(const hashkey& h) const;
	std::string key_string() const;
	hashkey(std::string keystring); 
	bool initialized() const { return key != nullptr && md_hash::valid(hashalgo, keysize); }
};
inline std::ostream& operator<< (std::ostream& out, const hashkey& hk)
{
	out << hk.key_string();
	return out;
}


// std::hash specialization for hashkey
namespace std
{
template<>
struct hash<hashkey>
{
	size_t operator()(const hashkey& hk) const { 
		size_t rv = 0;
		if(hk.get_raw() != nullptr)
			memcpy(&rv, hk.get_raw(), std::min<size_t>(hk.size(), sizeof(size_t)));
		return rv;
	}
};
}

class byte_array
{
protected:
	uint8_t* data;
	size_t length;
public:
	byte_array() : data(nullptr), length(0) { }
	byte_array(const uint8_t* d, size_t size) : data((size!=0) ? new uint8_t[size] : nullptr), length(size) { if(size) memcpy(data, d, size); }
	byte_array(const byte_array& other) : byte_array(other.data, other.length) { }
	byte_array(byte_array&& other) : data(other.data), length(other.length) { other.data = nullptr; }
	byte_array& operator=(const byte_array& other);
	byte_array& operator=(byte_array&& other);
	bool operator<(const byte_array& c) const {
		int rv = memcmp(data, c.data, std::min(length, c.length));
		return (rv!=0) ? (rv < 0) : (length < c.length);
	}
	bool operator==(const byte_array& other) const { return length == other.length && is_equal(data, other.data, length); }
	// not virtual: don't access/delete subclasses through byte_array pointers
	~byte_array();
	bool operator!=(const byte_array& other) { return !(*this==other); }
	bool initialized() { return data != nullptr; }
	const uint8_t* get_raw() const { return data; }
	size_t len() const { return length; }
};

class der_pubkey : public byte_array
{
private:
	void convert_pubkey(EVP_PKEY* pubkey);
public:
	// expose byte_array constructors:
	template<class...Args> inline der_pubkey(Args&&... args) : der_pubkey::byte_array(std::forward<Args>(args)...) {}
	der_pubkey(X509* cert);
	der_pubkey(EVP_PKEY* pubkey) { convert_pubkey(pubkey); }
	hashkey get_hashkey(uint16_t algo, uint16_t hash_len) const {
		return (data != nullptr) ? hashkey(data, length, algo, hash_len) : hashkey();
	}
};

class digital_signature : public byte_array
{
private:
	uint16_t digest_algo;
	uint16_t digest_len;
public:
	// expose byte_array constructors:
	template<typename...Args> inline digital_signature(Args&&... args) : digital_signature::byte_array(std::forward<Args>(args)...) {}
	digital_signature() : byte_array() {}
	digital_signature(uint16_t algo, uint16_t hashlen) : byte_array(nullptr, 0), digest_algo(algo), digest_len(hashlen) {}
	void assign_sig(uint8_t* sig, size_t size) {
		if(data != nullptr)
			delete[] data;
		data = sig;
		length = size;
	}
	uint16_t md_algo() const { return digest_algo; }
	uint16_t md_len() const { return digest_len; }
};

class digital_signature_signer
{
private:
	EVP_PKEY* privkey;
	EVP_MD_CTX* md_ctx;
	digital_signature sig;
public:
	digital_signature_signer(const char* privkey_file, uint16_t hash_algo, uint16_t hashlen);
	void update(const uint8_t *data, size_t len);
	const digital_signature& get_signature();
	~digital_signature_signer();
};

class digital_signature_verify
{
private:
	EVP_MD_CTX* md_ctx;
public:
	digital_signature_verify(const der_pubkey& pubkey, uint16_t hash_algo, uint16_t hashlen)
		: digital_signature_verify(pubkey.get_raw(), pubkey.len(), hash_algo, hashlen) {}
	digital_signature_verify(const uint8_t* pubkey, size_t keylen, uint16_t hash_algo, uint16_t hashlen);
	digital_signature_verify(const digital_signature_verify&) = delete;
	void update(const uint8_t *data, size_t len);
	bool verify_final(const uint8_t* sig, const size_t siglen);
	~digital_signature_verify() {
		if(md_ctx != nullptr)
			EVP_MD_CTX_destroy(md_ctx);
	}
};


#endif // CRYPTO_H
