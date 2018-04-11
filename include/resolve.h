#ifdef RESOLVE_H
#define RESOLVE_H

int
create_resolver(ldns_resolver** res, char* serv);

int
query(ldns_pkt** p, ldns_resolver* res, ldns_rdf* domain, ldns_rr_type rtype);

int
get_key(char** keystr, char* keynamestr, int ksk);

int
verify_trust(ldns_dnssec_data_chain** chain, ldns_dnssec_trust_tree** tree,
			 ldns_resolver* res, ldns_rr_list* rrlist, ldns_pkt* pkt);

int
check_trustedkeys(ldns_dnssec_trust_tree* tree, ldns_rr_list* trustedkeys);

int
trustedkey_fromkey(ldns_rr* rr_trustedkey, char* key, char* domain,
				   int ksk);

int
addto_trustedkeys(ldns_rr_list* rrset_trustedkeys, ldns_rr* rr_trustedkey);

int
populate_trustedkeys(ldns_rr_list* rrset_trustedkeys, char* domain);

int
verify_rr(ldns_rr_list* rrset, ldns_rr_list* rrsig, char* domain,
		  ldns_rr_type rtype);

#endif
