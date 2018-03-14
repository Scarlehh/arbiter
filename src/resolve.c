/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#include "resolve.h"

/* return type of gai_strerror */
#define IRS_GAISTRERROR_RETURN_T const char *

/* Define to the buffer length type used by getnameinfo(3). */
#define IRS_GETNAMEINFO_BUFLEN_T socklen_t

/* Define to the flags type used by getnameinfo(3). */
#define IRS_GETNAMEINFO_FLAGS_T int

/* Define to the sockaddr length type used by getnameinfo(3). */
#define IRS_GETNAMEINFO_SOCKLEN_T socklen_t

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <netdb.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/base64.h>
#include <isc/buffer.h>
#include <isc/commandline.h>
#include <isc/lib.h>
#include <isc/mem.h>
#include <isc/print.h>
#include <isc/sockaddr.h>
#include <isc/util.h>
#include <isc/app.h>
#include <isc/task.h>
#include <isc/socket.h>
#include <isc/timer.h>

#include <irs/resconf.h>
#include <irs/netdb.h>

#include <dns/client.h>
#include <dns/fixedname.h>
#include <dns/keyvalues.h>
#include <dns/lib.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatastruct.h>
#include <dns/rdatatype.h>
#include <dns/result.h>
#include <dns/secalg.h>

#include <dst/dst.h>

isc_result_t printdata(dns_rdataset_t *rdataset, dns_name_t *owner) {
    isc_buffer_t target;
    isc_result_t result;
    isc_region_t r;
    char t[4096];

    if (!dns_rdataset_isassociated(rdataset)) {
        printf("[WARN: empty]\n");
        return (ISC_R_SUCCESS);
    }

    isc_buffer_init(&target, t, sizeof(t));

    result = dns_rdataset_totext(rdataset, owner, ISC_FALSE, ISC_FALSE,
                     &target);
    if (result != ISC_R_SUCCESS)
        return (result);
    isc_buffer_usedregion(&target, &r);
    printf("%.*s", (int)r.length, (char *)r.base);

    return (ISC_R_SUCCESS);
}

void set_key(dns_client_t *client, char *keynamestr, char *keystr,
			 isc_boolean_t is_sep, isc_mem_t **mctxp, char *algname)
{
    isc_result_t result;
    dns_fixedname_t fkeyname;
    unsigned int namelen;
    dns_name_t *keyname;
    dns_rdata_dnskey_t keystruct;
    unsigned char keydata[4096];
    isc_buffer_t keydatabuf;
    unsigned char rrdata[4096];
    isc_buffer_t rrdatabuf;
    isc_buffer_t b;
    isc_textregion_t tr;
    isc_region_t r;
    dns_secalg_t alg;

    result = isc_mem_create(0, 0, mctxp);
    if (result != ISC_R_SUCCESS) {
        fprintf(stderr, "failed to create mctx\n");
        exit(1);
    }

    if (algname != NULL) {
        tr.base = algname;
        tr.length = strlen(algname);
        result = dns_secalg_fromtext(&alg, &tr);
        if (result != ISC_R_SUCCESS) {
            fprintf(stderr, "failed to identify the algorithm\n");
            exit(1);
        }
    } else
        alg = DNS_KEYALG_RSASHA1;

    keystruct.common.rdclass = dns_rdataclass_in;
    keystruct.common.rdtype = dns_rdatatype_dnskey;
    keystruct.flags = DNS_KEYOWNER_ZONE; /* fixed */
    if (is_sep)
        keystruct.flags |= DNS_KEYFLAG_KSK;
    keystruct.protocol = DNS_KEYPROTO_DNSSEC; /* fixed */
    keystruct.algorithm = alg;

    isc_buffer_init(&keydatabuf, keydata, sizeof(keydata));
    isc_buffer_init(&rrdatabuf, rrdata, sizeof(rrdata));
    result = isc_base64_decodestring(keystr, &keydatabuf);
    if (result != ISC_R_SUCCESS) {
        fprintf(stderr, "base64 decode failed\n");
        exit(1);
    }
    isc_buffer_usedregion(&keydatabuf, &r);
    keystruct.datalen = r.length;
    keystruct.data = r.base;

    result = dns_rdata_fromstruct(NULL, keystruct.common.rdclass,
                      keystruct.common.rdtype,
                      &keystruct, &rrdatabuf);
    if (result != ISC_R_SUCCESS) {
        fprintf(stderr, "failed to construct key rdata\n");
        exit(1);
    }
    namelen = strlen(keynamestr);
    isc_buffer_init(&b, keynamestr, namelen);
    isc_buffer_add(&b, namelen);
    dns_fixedname_init(&fkeyname);
    keyname = dns_fixedname_name(&fkeyname);
    result = dns_name_fromtext(keyname, &b, dns_rootname, 0, NULL);
    if (result != ISC_R_SUCCESS) {
        fprintf(stderr, "failed to construct key name\n");
        exit(1);
    }
    result = dns_client_addtrustedkey(client, dns_rdataclass_in,
                      keyname, &rrdatabuf);
    if (result != ISC_R_SUCCESS) {
        fprintf(stderr, "failed to add key for %s\n",
            keynamestr);
        exit(1);
    }
}

void addserver(dns_client_t *client, const char *addrstr, const char *port,
			   const char *name_space)
{
    struct addrinfo hints, *res;
    int gaierror;
    isc_sockaddr_t sa;
    isc_sockaddrlist_t servers;
    isc_result_t result;
    unsigned int namelen;
    isc_buffer_t b;
    dns_fixedname_t fname;
    dns_name_t *name = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_NUMERICHOST;
    gaierror = getaddrinfo(addrstr, port, &hints, &res);
    if (gaierror != 0) {
        fprintf(stderr, "getaddrinfo failed: %s\n",
            gai_strerror(gaierror));
        exit(1);
    }
    INSIST(res->ai_addrlen <= sizeof(sa.type));
    memmove(&sa.type, res->ai_addr, res->ai_addrlen);
    sa.length = (unsigned int)res->ai_addrlen;
    freeaddrinfo(res);
    ISC_LINK_INIT(&sa, link);
    ISC_LIST_INIT(servers);
    ISC_LIST_APPEND(servers, &sa, link);

    if (name_space != NULL) {
        namelen = strlen(name_space);
        isc_buffer_constinit(&b, name_space, namelen);
        isc_buffer_add(&b, namelen);
        dns_fixedname_init(&fname);
        name = dns_fixedname_name(&fname);
        result = dns_name_fromtext(name, &b, dns_rootname, 0, NULL);
        if (result != ISC_R_SUCCESS) {
            fprintf(stderr, "failed to convert qname: %u\n",
                result);
            exit(1);
        }
    }

    result = dns_client_setservers(client, dns_rdataclass_in, name,
                       &servers);
    if (result != ISC_R_SUCCESS) {
        fprintf(stderr, "set server failed: %u\n", result);
        exit(1);
    }
}
