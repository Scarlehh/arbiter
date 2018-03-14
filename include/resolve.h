#ifndef RESOLVE_H
#define RESOLVE_H

#include <isc/base64.h>

#include <dns/client.h>

static isc_result_t
printdata(dns_rdataset_t *rdataset, dns_name_t *owner);

ISC_PLATFORM_NORETURN_PRE static void
usage(void) ISC_PLATFORM_NORETURN_POST;

static void
set_key(dns_client_t *client, char *keynamestr, char *keystr,
		isc_boolean_t is_sep, isc_mem_t **mctxp);

static void
addserver(dns_client_t *client, const char *addrstr, const char *port,
		  const char *name_space);

#endif
