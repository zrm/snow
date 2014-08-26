/*	sdns
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

#ifndef DNS_RESPONSE_H
#define DNS_RESPONSE_H
#include <vector>
#include "dns_message.h"

struct dns_response
{
	std::vector< dns_record<cname_rdata> > cname_chain;
	std::vector<dns_rrset> ancillary; // any records for answer section other than CNAME or final answer, or all records for wildcard querys
	dns_rcode_t rcode;
	virtual bool nodata() const { return false; }
	virtual const dns_record<soa_rdata> *ncache_soa() const { return nullptr; } // MAY exist if rcode==NAME_ERROR or (rcode==NO_ERROR && nodata()==true) (and upstream provided it)
	virtual const dns_rrset *final_answer() const { return nullptr; } // exists if rcode==NO_ERROR and nodata()==false
	dns_response(dns_rcode_t rc, std::vector< dns_record<cname_rdata> > &&cnames = std::vector< dns_record<cname_rdata> >(), std::vector<dns_rrset> &&anc = std::vector<dns_rrset>())
		: cname_chain(std::move(cnames)), ancillary(std::move(anc)), rcode(rc) {}
	virtual ~dns_response() {}
	virtual std::unique_ptr<dns_response> clone() const { return std::unique_ptr<dns_response>(new dns_response(*this)); }
	virtual bool operator==(const dns_response & dr) {
		if(rcode != dr.rcode) return false;
		if(cname_chain.size() != dr.cname_chain.size()) return false;
		if(ancillary.size() != dr.ancillary.size()) return false;
		for(size_t i=0; i < dr.cname_chain.size(); ++i)
			if(std::find(cname_chain.begin(), cname_chain.end(), dr.cname_chain[i]) == cname_chain.end())
				return false;
		for(size_t i=0; i < dr.ancillary.size(); ++i)
			if(std::find(ancillary.begin(), ancillary.end(), dr.ancillary[i]) == ancillary.end())
				return false;
		return true;
	}
	bool operator!=(const dns_response & dr) { return !(*this == dr); }
};

struct dns_response_answer : public dns_response
{
	dns_rrset answer; // actual final answer rrset, note that this is not necessarily a match for question (could be CNAME target)
	virtual const dns_rrset *final_answer() const override { return &answer; }
	dns_response_answer(dns_rcode_t rc, const dns_rrset &ans,
		std::vector< dns_record<cname_rdata> > &&cnames = std::vector< dns_record<cname_rdata> >(), std::vector<dns_rrset> &&anc = std::vector<dns_rrset>())
			: dns_response(rc, std::move(cnames), std::move(anc)), answer(ans) {}
	dns_response_answer(dns_rcode_t rc, const domain_name &ans_name, const rrset_data &ans,
		std::vector< dns_record<cname_rdata> > &&cnames = std::vector< dns_record<cname_rdata> >(), std::vector<dns_rrset> &&anc = std::vector<dns_rrset>())
			: dns_response(rc, std::move(cnames), std::move(anc)), answer(ans_name, ans) {}
	virtual std::unique_ptr<dns_response> clone() const override { return std::unique_ptr<dns_response>(new dns_response_answer(*this)); }
	virtual bool operator==(const dns_response & dr) {
		if( ! dns_response::operator==(dr) ) return false;
		const dns_rrset *ans = dr.final_answer();
		if(ans == nullptr) return false;
		return *ans == answer;
	}
};

struct dns_response_wildcard_answer : public dns_response
{
	dns_response_wildcard_answer(std::vector<dns_rrset> &&records, dns_rcode_t rc)
		: dns_response(rc, std::vector< dns_record<cname_rdata> >(), std::move(records)) {}
	virtual std::unique_ptr<dns_response> clone() const override { return std::unique_ptr<dns_response>(new dns_response_wildcard_answer(*this)); }
};

// dns_response_nx: NXDOMAIN or NODATA (distinguish based on rcode)
struct dns_response_nx : public dns_response
{
	std::unique_ptr< dns_record<soa_rdata> > soa;
	virtual dns_record<soa_rdata> *ncache_soa() const override { return soa.get(); }
	dns_response_nx(dns_rcode_t rc, const dns_rrset *soa_rrset, std::vector< dns_record<cname_rdata> > &&cnames = std::vector< dns_record<cname_rdata> >())
		: dns_response(rc, std::move(cnames)) {
		if(soa_rrset != nullptr && soa_rrset->record_count() == 1) {
			soa.reset(new dns_record<soa_rdata>(soa_rrset->get_name(), soa_rrset->get_type(), soa_rrset->get_class(),
												soa_rrset->get_ttl(), soa_rrset->rrdata->get<soa_rdata>().rdata.front()));
		}
	}
	dns_response_nx(dns_rcode_t rc, std::unique_ptr< dns_record<soa_rdata> > soa_rec) : dns_response(rc), soa(std::move(soa_rec)) {}
	dns_response_nx(const dns_response_nx& drn) : dns_response(drn), soa(drn.soa == nullptr ? nullptr : new dns_record<soa_rdata>(*drn.soa)) {}
	virtual std::unique_ptr<dns_response> clone() const override { return std::unique_ptr<dns_response>(new dns_response_nx(*this)); }
	virtual bool nodata() const override { return rcode == dns_rcode_t::DNS_NO_ERROR; }
	virtual bool operator==(const dns_response & dr) {
		if( ! dns_response::operator==(dr) ) return false;
		if(soa == nullptr || dr.ncache_soa() == nullptr) return soa.get() == dr.ncache_soa();
		return *soa == *dr.ncache_soa();
	}
};

struct dns_response_error : public dns_response
{
	dns_response_error(dns_rcode_t rc) : dns_response(rc) {}
	virtual std::unique_ptr<dns_response> clone() const override { return std::unique_ptr<dns_response>(new dns_response_error(*this)); }
};


#endif // DNS_RESPONSE_H
