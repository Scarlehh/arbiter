#include "resolve.h"

#include <stdio.h>
#include <stdlib.h>

#include <ldns/ldns.h>

#define ZONEDATA "zonedata.txt"
#define MAXBUF 1024

int verbosity = 0;

struct rrsig_info {
	int bytes;
	int algorithm
};

int
count_lines() {
	FILE *file = fopen(ZONEDATA, "r");

	if (file == NULL)
		return -1;

	char line[MAXBUF];

	// Skip a line
	if (fgets(line, sizeof(line), file) == NULL)
		return -1;

	int linecount = 0;
	while(fgets(line, sizeof(line), file) != NULL) {
		linecount++;
	}
	return linecount;
}

int
get_dnssec_zones(char** zones, int linecount) {
	FILE *file = fopen(ZONEDATA, "r");

	if (file == NULL)
		return -1;

	char line[MAXBUF];

	// Skip a line
	if (fgets(line, sizeof(line), file) == NULL)
		return -1;

	char zone[MAXBUF];
	char type[52];
	int z = 0;
	for(int i = 0; i < linecount; i++) {
		fscanf(file, "%s %*s %*s %s", zone, type);

		if ((z == 0) || (strcmp(zones[z-1], zone) != 0)) {
			if (strcmp(type, "rrsig") == 0) {
				zones[z] = malloc(sizeof(zone));
				memcpy(zones[z], zone, sizeof(zone));
				z++;
			}
		}
		fgets(line, sizeof(line), file);
	}
	return z;
}

int
check_dnssec(char* domain_name, ldns_resolver* res, struct rrsig_info* info) {
	ldns_rdf* domain = ldns_dname_new_frm_str(domain_name);
	ldns_pkt* pkt;
	query(&pkt, res, domain, LDNS_RR_TYPE_A);
	ldns_rr_list* rrset =
		ldns_pkt_rr_list_by_type(pkt, LDNS_RR_TYPE_RRSIG, LDNS_SECTION_ANSWER);
	if (!rrset) {
		rrset = ldns_pkt_rr_list_by_type(pkt, LDNS_RR_TYPE_RRSIG,
										 LDNS_SECTION_AUTHORITY);
		if (!rrset) {
			ldns_pkt_free(pkt);
			ldns_rdf_deep_free(domain);
			return 0;
		}
	}
	info->bytes = ldns_pkt_size(pkt);
	info->algorithm = ldns_rdf2native_int8(ldns_rr_rdf(ldns_rr_set_pop_rr(rrset),1));

	ldns_rr_list_deep_free(rrset);
	ldns_pkt_free(pkt);
	ldns_rdf_deep_free(domain);
	return 1;
}

int
main(void) {
	int linecount = count_lines();
	char** zones = malloc(sizeof(char*)*linecount);
	linecount = get_dnssec_zones(zones, linecount);

	printf("%-30s\t\t%s\t\t%s\n"
		   "%-30s\t\t-----\t\t---------\n",
		   "Domain name", "Bytes", "Algorithm", "-----------");
	for(int i = 0; i < linecount; i++) {
		// Create resolver
		ldns_resolver *res;
		int result = create_resolver(&res, NULL);
		if (result != EXIT_SUCCESS)
			goto exit;

		// Configure resolver
		ldns_resolver_set_dnssec(res, true);
		ldns_resolver_set_dnssec_cd(res, true);
		ldns_resolver_set_ip6(res, LDNS_RESOLV_INETANY);
		if (!res) {
			result = 2;
			goto exit;
		}

		struct rrsig_info info;
		if(check_dnssec(zones[i], res, &info)) {
			printf("%-30s\t\t%d\t\t%d\n", zones[i], info.bytes, info.algorithm);
		}

		ldns_resolver_deep_free(res);
	}

 exit:

	for(int i = 0; i < linecount; i++) {
		free(zones[i]);
	}
	free(zones);
	return 0;
}
