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

#include<sstream>
#include"crypto.h"

const EVP_MD* md_hash::evp_md(uint16_t hash_algo, uint16_t hashlen)
{
	const EVP_MD* rv = nullptr;
	switch(hash_algo) {
	case SHA2:
		switch(hashlen) {
		case 224/8:
			rv = EVP_sha224();
			break;
		case 256/8:
			rv = EVP_sha256();
			break;
		case 384/8:
			rv = EVP_sha384();
			break;
		case 512/8:
			rv = EVP_sha512();
			break;
		}
		break;
	case WHIRL_POOL:
		if(hashlen == 512/8)
			rv = EVP_whirlpool();
		break;
	}
	return rv;
}

md_hash::md_hash(uint16_t hash_algo, uint16_t hash_len) : mdctx(nullptr), hashlen(hash_len)
{
	const EVP_MD* md = evp_md(hash_algo, hash_len);
	if(md != nullptr) {
		mdctx = EVP_MD_CTX_create();
		EVP_DigestInit_ex(mdctx, md, nullptr);
	}
}

void md_hash::digest(uint16_t hash_algo, uint16_t hashlen, const uint8_t *data, size_t data_len, uint8_t *md)
{
	switch(hash_algo) {
	case SHA2:
		switch(hashlen) {
		case 224/8:
			SHA224(data, data_len, md);
			break;
		case 256/8:
			SHA256(data, data_len, md);
			break;
		case 384/8:
			SHA384(data, data_len, md);
			break;
		case 512/8:
			SHA512(data, data_len, md);
			break;
		}
		break;
	case WHIRL_POOL:
		if(hashlen==512/8)
			WHIRLPOOL(data, data_len, md);
		break;
	}
}

hashkey::hashkey(const uint8_t *data, size_t datalen, uint16_t h_algo, uint16_t hashlen): hashalgo(h_algo), keysize(hashlen)
{
	if(!md_hash::valid(h_algo, hashlen)) {
		wout() << "hashkey constructor got unknown hash algorithm or digest size, defaulting to SHA256";
		hashalgo = md_hash::SHA2;
		keysize = 32;
	}
	key = new uint8_t[keysize];
	md_hash::digest(hashalgo, keysize, data, datalen, key);
}

hashkey& hashkey::operator=(const hashkey& h)
{
	if(key != nullptr && keysize != h.keysize) {
		delete[] key;
		key = nullptr;
	}
	if(key==nullptr && h.key != nullptr)
		key = new uint8_t[h.keysize];
	keysize = h.keysize;
	hashalgo = h.hashalgo;
	memcpy(key, h.key, keysize);
	return *this;
}

hashkey& hashkey::operator=(hashkey&& h)
{
	keysize = h.keysize;
	hashalgo = h.hashalgo;
	std::swap(key, h.key);
	return *this;
}

bool hashkey::operator<(const hashkey& h) const
{
	int rv = memcmp(key, h.key, std::min(keysize, h.keysize));
	if(rv != 0)
		return rv < 0;
	if(keysize != h.keysize)
		return keysize < h.keysize;
	return hashalgo < h.hashalgo;
}

std::string hashkey::key_string() const
{
	// keystring format: pad char + multiple-of-five char base32 encoded algo and key + (optional) ".key"
	// TODO: for some hashkeys (> 256 bits) this can produce a keystring with more than 63 chars (which DNS doesn't like)
		// for now SHA256 is the default and using longer is broken/unimplemented, but at some point devise some encoding for longer keys (e.g. use multiple labels)
	if(key == nullptr || keysize==0)
		return "[uninitialized]";
	if(keysize <= 8) {
		// key is not a valid hashkey, seems to be 'data' type, show as hex
		std::stringstream ss;
		ss << "[0x";
		for(size_t i=0; i < keysize; ++i)
			ss << std::hex << (int)key[i];
		ss << "]";
		return ss.str();
	}
	size_t outsize = keysize + sizeof(uint16_t);
	size_t pad = (5 - (outsize % 5)) % 5;
	outsize = (outsize + pad) * 8 / 5 + 6; // base32-encoded size + 6 for pad count char, ".key" and '\0' 
	char out[outsize];
	out[0] = 'a' + pad; // record amount of padding as char a through e, and ensure that at least one char is alpha not numeric to make DNS happy [even though all-numeric is statistically impossible]
	strcpy(out+outsize-strlen(".key")-1, ".key");
	uint8_t tmp[10];
	for(unsigned i=0; i < pad; ++i)
		tmp[i] = 0;
	tmp[pad] = hashalgo >> 8;
	tmp[pad+1] = hashalgo & 0xff;
	unsigned key_index = 0;
	for(unsigned i=pad+2; i < 10; ++key_index, ++i)
		tmp[i] = key[key_index];
	unsigned out_offset = 1; // for pad char
	base32_encode(tmp, out + out_offset);
	out_offset += 8;
	base32_encode(tmp+5, out + out_offset);
	out_offset += 8;
	for(; key_index < keysize; out_offset += 8, key_index += 5)
		base32_encode(key + key_index, out + out_offset);
	return std::string(out);
}

hashkey::hashkey(std::string keystring): key(nullptr), hashalgo(0), keysize(0)
{
	size_t strsize = keystring.size();
	if(strsize < 22) {
		// no valid string is this short and now we can assume at least that much exists (i.e. 16 + pad char + ".key.")
		return;
	}
	int pad = keystring[0] - 'a';
	if(pad > 4 || pad < 0) {
		pad = keystring[0] - 'A';
		if(pad > 4 || pad < 0) {
			dout() << "hashkey keystring had invalid pad count";
			return;
		}
	}
	if(keystring.substr(strsize-4, 4) == ".key")
		strsize -= 4;
	else if(keystring.substr(strsize-5, 5) == ".key.")
		strsize -= 5;
	strsize -= 1; // pad char
	if((strsize & 3) != 0) {
		// actual number of data bits not divisible by 8 as required
		dout() << "hashkey keystring had invalid number of characters";
		return;
	}
	keysize = strsize / 8 * 5 - sizeof(uint16_t) - pad;
	key = new uint8_t[keysize];
	const char *data = keystring.c_str() + 1/*pad char*/;
	uint8_t tmp[10];
	try {
		base32_decode(data, tmp);
		base32_decode(data + 8, tmp + 5);
		hashalgo = (static_cast<uint16_t>(tmp[pad]) << 8) + tmp[pad+1];
		// copy tmp into key instead of putting there directly b/c hashalgo would make offset wrong
		unsigned key_index = 0;
		for(unsigned i = pad+2; i < 10; ++i, ++key_index)
			key[key_index] = tmp[i]; 
		for(data = data + 16; key_index < keysize; data += 8, key_index += 5)
			base32_decode(data, key + key_index);
	} catch(const e_invalid_input &) {
		delete[] key;
		key = nullptr;
		keysize = 0;
		dout() << "hashkey(keystring) got invalid input";
	}
}

byte_array& byte_array::operator=(const byte_array& other)
{
	if(data != nullptr)
		delete[] data;
	length = other.length;
	if(other.data != nullptr)
	{
		data = new uint8_t[other.length];
		memcpy(data, other.data, length);
	} else {
		data = nullptr;
	}
	return *this;
}

byte_array& byte_array::operator=(byte_array&& other)
{
   length = other.length;
   std::swap(data, other.data);
   return *this;
}

byte_array::~byte_array()
{
	if(data != nullptr)
	   delete[] data;
}

void der_pubkey::convert_pubkey(EVP_PKEY *pubkey)
{
	int size = i2d_PUBKEY(pubkey, nullptr);
	if(size > 0) {
		data = new uint8_t[size];
		length = size;
		uint8_t* tmp = data;
		i2d_PUBKEY(pubkey, &tmp);
	} else {
		data = nullptr;
		length = 0;
		eout() << "Could not convert EVP public key to DER";
	}
}

der_pubkey::der_pubkey(X509 *cert): byte_array()
{
	if(cert != nullptr) {
		EVP_PKEY* pubkey = X509_get_pubkey(cert);
		if(pubkey != nullptr) {
			convert_pubkey(pubkey);
			EVP_PKEY_free(pubkey);
		}
	}
}

digital_signature_signer::digital_signature_signer(const char *privkey_file, uint16_t hash_algo, uint16_t hashlen): privkey(nullptr), md_ctx(nullptr)
{
	FILE* fp = fopen(privkey_file, "r");
	if(fp != nullptr) {
		privkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
		fclose(fp);
		if(privkey != nullptr) {
			sig = digital_signature(hash_algo, hashlen);
			md_ctx = EVP_MD_CTX_create();
			if(md_ctx != nullptr) {
				EVP_MD_CTX_init(md_ctx);
				if(!EVP_DigestSignInit(md_ctx, nullptr, md_hash::evp_md(hash_algo, hashlen), privkey->engine,privkey)) {
					EVP_MD_CTX_destroy(md_ctx);
					md_ctx = nullptr;
				}
			}
		}
	}
}

void digital_signature_signer::update(const uint8_t *data, size_t len)
{
	if(md_ctx != nullptr) {
		if(!EVP_DigestSignUpdate(md_ctx, data, len)) {
			EVP_MD_CTX_destroy(md_ctx);
			md_ctx = nullptr;
		}
	}
}

const digital_signature& digital_signature_signer::get_signature()
{
	if(md_ctx != nullptr && privkey != nullptr) {
		size_t siglen = EVP_PKEY_size(privkey);
		uint8_t* sig_data = new uint8_t[siglen];
		if(EVP_DigestSignFinal(md_ctx, sig_data, &siglen))
			sig.assign_sig(sig_data, siglen);
		// done with this now, and setting it to nullptr will prevent calling DigestSignFinal twice
		EVP_MD_CTX_destroy(md_ctx);
		md_ctx = nullptr;
	}
	return sig;
}

digital_signature_signer::~digital_signature_signer()
{
	if(privkey != nullptr)
		EVP_PKEY_free(privkey);
	if(md_ctx != nullptr) {
		EVP_MD_CTX_destroy(md_ctx);
	}
}

digital_signature_verify::digital_signature_verify(const uint8_t *pubkey, size_t keylen, uint16_t hash_algo, uint16_t hashlen) : md_ctx(nullptr)
{
	EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &pubkey, keylen); // makes der_pubkey pointer point somewhere else, but we don't need it anymore anyway
	if(pkey != nullptr) {
		md_ctx = EVP_MD_CTX_create();
		if(md_ctx != nullptr) {
			EVP_MD_CTX_init(md_ctx);
			if(!EVP_DigestVerifyInit(md_ctx, nullptr, md_hash::evp_md(hash_algo, hashlen), pkey->engine, pkey)) {
				EVP_MD_CTX_destroy(md_ctx);
				md_ctx = nullptr;
			}
		}
		EVP_PKEY_free(pkey);
	}
}

void digital_signature_verify::update(const uint8_t *data, size_t len)
{
	if(md_ctx != nullptr) {
		if(!EVP_DigestVerifyUpdate(md_ctx, data, len)) {
			EVP_MD_CTX_destroy(md_ctx);
			md_ctx = nullptr;
		}
	}
}

bool digital_signature_verify::verify_final(const uint8_t *sig, const size_t siglen)
{
	// current OpenSSL requires non-const signature here for no apparent reason (and signatures are large)
	// TODO: stop using OpenSSL
	uint8_t sig_copy[siglen];
	memcpy(sig_copy, sig, siglen);
	return md_ctx != nullptr && EVP_DigestVerifyFinal(md_ctx, sig_copy, siglen);
}
