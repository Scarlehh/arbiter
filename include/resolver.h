#ifdef RESOLVER_H
#define RESOLVER_H

int
create_resolver(char* serv, ldns_resolver** res);

int
query(ldns_resolver* res, char* domain, ldns_rr_type rtype, ldns_pkt** p);

#endif
