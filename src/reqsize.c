#include "resolve.h"

#include <stdio.h>
#include <stdlib.h>

#include <ldns/ldns.h>

#define ZONEDATA "zonedata.txt"
#define MAXBUF 1024

int verbosity = 0;

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
	printf("Line count: %d\n", linecount);
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
	printf("Final line count: %d\n", z);
	return z;
}

int
check_dnssec(char* domain_name, ldns_resolver* res) {
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
			return false;
		}
	}

	ldns_rr_list_deep_free(rrset);
	ldns_pkt_free(pkt);
	ldns_rdf_deep_free(domain);
	return true;
}

int
main(void) {
	int linecount = count_lines();
	char** zones = malloc(sizeof(char*)*linecount);
	linecount = get_dnssec_zones(zones, linecount);

	for(int i = 0; i < linecount; i++) {
		printf("%s\n", zones[i]);
	}

 exit:

	for(int i = 0; i < linecount; i++) {
		free(zones[i]);
	}
	free(zones);
	return 0;
}
