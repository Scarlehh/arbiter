#ifdef RESOLVER_H
#define RESOLVER_H

int
create_resolver(ldns_resolver** res, char* serv);

int
query(ldns_pkt** p, ldns_resolver* res, ldns_rdf* domain, ldns_rr_type rtype);

int
get_key(char** keystr, char* keynamestr);

int
create_verifier(ldns_dnssec_data_chain** chain, ldns_dnssec_trust_tree** tree,
				ldns_resolver* res, ldns_rr_list* rrlist, ldns_pkt* pkt);

int
verify(ldns_dnssec_trust_tree* tree, ldns_rr_list* trustedkeys);

int
trustedkey_fromkey(ldns_rr_list* rrset_trustedkeys, char* key, char* domain,
				   int ksk);

#endif
