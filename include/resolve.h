#ifndef RESOLVE_H
#define RESOLVE_H

#include <isc/base64.h>

#include <dns/client.h>

isc_result_t
create_dnsclient(isc_mem_t **mctx, isc_appctx_t **actx,
				 isc_taskmgr_t **taskmgr, isc_socketmgr_t **socketmgr,
				 isc_timermgr_t **timermgr, dns_client_t **client,
				 isc_sockaddr_t *addr4, isc_sockaddr_t *addr6);

isc_result_t
printdata(dns_rdataset_t *rdataset, dns_name_t *owner);

void
set_key(dns_client_t *client, char *keynamestr, char *keystr,
		isc_boolean_t is_sep, isc_mem_t **mctxp, char *algname);

void
set_defserver(isc_mem_t *mctx, dns_client_t *client);

void
addserver(dns_client_t *client, const char *addrstr, const char *port,
		  const char *name_space);

#endif
