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
#include "helper.h"

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

#include <mysql/mysql.h>

#include <openssl/pem.h>

#define CONFIG_FILE "config.conf"
#define MAXBUF 1024

isc_result_t
get_mysql_cert(char* configfile, char* domain, char** cert) {
	MYSQL* con = mysql_init(NULL);
	if (con == NULL) {
		fprintf(stderr, "mysql_init() failed\n");
		return ISC_R_CONNREFUSED;
	}

	isc_result_t result;
	struct dbconfig config;
	get_config(configfile, &config);

	if (mysql_real_connect(con, "localhost", config.username, config.password,
						   config.dbname, 0, NULL, 0) == NULL) {
		fprintf(stderr, "%s\n", mysql_error(con));
		result = ISC_R_CONNREFUSED;
		goto finish;
	}

	char query[MAXBUF];
	sprintf(query, "SELECT cert FROM certificates where domain='%s'", domain);
	if (mysql_query(con, query)) {
		fprintf(stderr, "%s\n", mysql_error(con));
		result = ISC_R_FAILURE;
		goto finish;
	}

	MYSQL_RES* mysql_result = mysql_store_result(con);
	if (mysql_result == NULL) {
		fprintf(stderr, "%s\n", mysql_error(con));
		result = ISC_R_FAILURE;
		goto finish;
	}

	MYSQL_ROW row = mysql_fetch_row(mysql_result);
	if (row == 0) {
		fprintf(stderr, "Domain is not registered in database\n");
		result = ISC_R_NOTFOUND;
		goto finish;
	} else if (row[0] == NULL) {
		result = ISC_R_SUCCESS;
		*cert = NULL;
		goto finish;
	}

	*cert = malloc(sizeof(char)*(strlen(row[0])+1));
	strncpy(*cert, *row, strlen(row[0])+1);
	mysql_free_result(mysql_result);
	result = ISC_R_SUCCESS;

 finish:
	mysql_close(con);
	free(config.username);
	free(config.password);
	free(config.dbname);
	return result;
}

isc_result_t
create_dnsclient(isc_mem_t **mctx, isc_appctx_t **actx,
				 isc_taskmgr_t **taskmgr, isc_socketmgr_t **socketmgr,
				 isc_timermgr_t **timermgr, dns_client_t **client,
				 isc_sockaddr_t *addr4, isc_sockaddr_t *addr6) {
	isc_result_t result;
	unsigned int clientopt;
	result = isc_mem_create(0, 0, mctx);
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr, "failed to crate mctx\n");
		return result;
	}

	result = isc_appctx_create(*mctx, actx);
	if (result != ISC_R_SUCCESS)
		return result;
	result = isc_app_ctxstart(*actx);
	if (result != ISC_R_SUCCESS)
		return result;
	result = isc_taskmgr_createinctx(*mctx, *actx, 1, 0, taskmgr);
	if (result != ISC_R_SUCCESS)
		return result;
	result = isc_socketmgr_createinctx(*mctx, *actx, socketmgr);
	if (result != ISC_R_SUCCESS)
		return result;
	result = isc_timermgr_createinctx(*mctx, *actx, timermgr);
	if (result != ISC_R_SUCCESS)
		return result;

	clientopt = 0;
	result = dns_client_createx2(*mctx, *actx, *taskmgr, *socketmgr, *timermgr,
								 clientopt, client, addr4, addr6);
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr, "dns_client_create failed: %u, %s\n", result,
			isc_result_totext(result));
		return result;
	}
	return result;
}

isc_result_t
printdata(dns_rdataset_t *rdataset, dns_name_t *owner) {
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

isc_result_t
set_key(dns_client_t *client, char *keynamestr, char *keystr,
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
        return result;
    }

    if (algname != NULL) {
        tr.base = algname;
        tr.length = strlen(algname);
        result = dns_secalg_fromtext(&alg, &tr);
        if (result != ISC_R_SUCCESS) {
            fprintf(stderr, "failed to identify the algorithm\n");
            return result;
        }
    } else
        alg = DNS_KEYALG_RSASHA1;

    keystruct.common.rdclass = dns_rdataclass_in;
    keystruct.common.rdtype = dns_rdatatype_dnskey;
    keystruct.flags = DNS_KEYOWNER_ZONE;
    if (is_sep)
        keystruct.flags |= DNS_KEYFLAG_KSK;
    keystruct.protocol = DNS_KEYPROTO_DNSSEC;
    keystruct.algorithm = alg;

    isc_buffer_init(&keydatabuf, keydata, sizeof(keydata));
    isc_buffer_init(&rrdatabuf, rrdata, sizeof(rrdata));
    result = isc_base64_decodestring(keystr, &keydatabuf);
    if (result != ISC_R_SUCCESS) {
        fprintf(stderr, "base64 decode failed\n");
        return result;
    }
    isc_buffer_usedregion(&keydatabuf, &r);
    keystruct.datalen = r.length;
    keystruct.data = r.base;

    result = dns_rdata_fromstruct(NULL, keystruct.common.rdclass,
                      keystruct.common.rdtype,
                      &keystruct, &rrdatabuf);
    if (result != ISC_R_SUCCESS) {
        fprintf(stderr, "failed to construct key rdata\n");
        return result;
    }
    namelen = strlen(keynamestr);
    isc_buffer_init(&b, keynamestr, namelen);
    isc_buffer_add(&b, namelen);
    dns_fixedname_init(&fkeyname);
    keyname = dns_fixedname_name(&fkeyname);
    result = dns_name_fromtext(keyname, &b, dns_rootname, 0, NULL);
    if (result != ISC_R_SUCCESS) {
        fprintf(stderr, "failed to construct key name\n");
        return result;
    }
    result = dns_client_addtrustedkey(client, dns_rdataclass_in,
                      keyname, &rrdatabuf);
    if (result != ISC_R_SUCCESS) {
        fprintf(stderr, "failed to add key for %s\n",
            keynamestr);
        return result;
    }
	return result;
}

isc_result_t
get_key(char *keynamestr, char **keystr) {
	char* cert;
	isc_result_t result = get_mysql_cert(CONFIG_FILE, keynamestr, &cert);
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr, "failed to get certificate from the database: %u\n",
				result);
		return result;
	}

	// Convert MYSQL query to X509
	BIO* cert_bio = BIO_new(BIO_s_mem());
	BIO_write(cert_bio, cert, strlen(cert));
	X509* certX509 = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
	free(cert);
	if (!certX509) {
		fprintf(stderr, "failed to parse certificate in memory\n");
		return ISC_R_FAILURE;
	}

	// Get public key from certificate
	EVP_PKEY* pkey = X509_get_pubkey(certX509);
	X509_free(certX509);
	BIO_free(cert_bio);
	if (!pkey) {
		fprintf(stderr, "failed to extract public key from certificate\n");
		return ISC_R_FAILURE;
	}

	// Convert public key to base64 encoding
	BIO* key_bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(key_bio, pkey);
	char *p;
	int read_size = (int) BIO_get_mem_data(key_bio, &p);
	EVP_PKEY_free(pkey);
	if (read_size < 1 || !p) {
		BIO_free(key_bio);
		fprintf(stderr, "failed to read public key\n");
		return ISC_R_FAILURE;
	}

	// Copy public key
	const char *KEY_START = "-----BEGIN PUBLIC KEY-----\n";
	const char *KEY_END = "-----END PUBLIC KEY-----";
	char* start = strstr(p, KEY_START);
	char* end = strstr(p, KEY_END);
	if (start && end) {
		start += strlen(KEY_START);
		*keystr = malloc(end-start+1);
		char* nl;
		char* keystart = *keystr;
		while ((nl = strstr(start, "\n")) < end) {
			memcpy(keystart, start, nl-start);
			keystart += nl-start;
			start = nl+1;
		}
		*keystart = '\0';
		result = ISC_R_SUCCESS;
	} else {
		fprintf(stderr, "failed to extract base64 from labels\n");
		result = ISC_R_FAILURE;
	}
	BIO_free(key_bio);

	return ISC_R_SUCCESS;
}

isc_result_t
set_defserver(isc_mem_t *mctx, dns_client_t *client) {
	isc_result_t result;
	irs_resconf_t *resconf = NULL;
	isc_sockaddrlist_t *nameservers;

	result = irs_resconf_load(mctx, "/etc/resolv.conf", &resconf);
	if (result != ISC_R_SUCCESS && result != ISC_R_FILENOTFOUND) {
		fprintf(stderr, "irs_resconf_load failed: %u\n",
				result);
		return result;
	}
	nameservers = irs_resconf_getnameservers(resconf);
	result = dns_client_setservers(client, dns_rdataclass_in,
								   NULL, nameservers);
	if (result != ISC_R_SUCCESS) {
		irs_resconf_destroy(&resconf);
		fprintf(stderr, "dns_client_setservers failed: %u\n",
				result);
		return result;
	}
	irs_resconf_destroy(&resconf);
	return result;
}

isc_result_t
addserver(dns_client_t *client, const char *addrstr, const char *port,
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
        return gaierror;
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
            return result;
        }
    }

    result = dns_client_setservers(client, dns_rdataclass_in, name,
                       &servers);
    if (result != ISC_R_SUCCESS) {
        fprintf(stderr, "set server failed: %u\n", result);
        return result;
    }
	return result;
}
