#include "resolve.h"

#include <stdio.h>
#include <stdlib.h>

#include <ldns/ldns.h>

#define ZONEDATA "zonedata.txt"
#define MAXBUF 1024
#define THREADS 32
#define RR LDNS_RR_TYPE_A

int verbosity = 0;

struct rrsig_info {
	int bytes;
	int algorithm
};

struct arg {
	char** zones;
	int linecount;
	int start;
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
	query(&pkt, res, domain, RR);
	ldns_rr_list* rrset =
		ldns_pkt_rr_list_by_type(pkt, RR, LDNS_SECTION_ANSWER);
	if (!rrset || !ldns_rr_list_rr_count(rrset))
		return 0;

	ldns_rr_list* rrsig =
		ldns_pkt_rr_list_by_type(pkt, LDNS_RR_TYPE_RRSIG, LDNS_SECTION_ANSWER);
	if (!rrsig) {
		ldns_pkt_free(pkt);
		ldns_rdf_deep_free(domain);
		return 0;
	}
	info->bytes = ldns_pkt_size(pkt);
	info->algorithm = ldns_rdf2native_int8(ldns_rr_rdf(ldns_rr_set_pop_rr(rrsig),1));

	ldns_rr_list_deep_free(rrset);
	ldns_pkt_free(pkt);
	ldns_rdf_deep_free(domain);
	return 1;
}

void*
request(void* arg) {
	struct arg* in = arg;
	char** zones = in->zones;
	int linecount = in->linecount;
	int start = in->start;

	for(int i = start; i < linecount; i+=THREADS) {
		// Create resolver
		ldns_resolver *res;
		int result = create_resolver(&res, NULL);
		if (result != EXIT_SUCCESS)
			continue;

		// Configure resolver
		ldns_resolver_set_dnssec(res, true);
		ldns_resolver_set_dnssec_cd(res, true);
		ldns_resolver_set_ip6(res, LDNS_RESOLV_INETANY);
		if (!res) {
			result = 2;
			continue;
		}

		struct rrsig_info info;
		if(check_dnssec(zones[i], res, &info)) {
			printf("%-50s\t\t%d\t\t%d\n", zones[i], info.bytes, info.algorithm);
		}

		ldns_resolver_deep_free(res);
	}
}

int
main(void) {
	int linecount = count_lines();
	char** zones = malloc(sizeof(char*)*linecount);
	linecount = get_dnssec_zones(zones, linecount);

	printf("%-50s\t\t%s\t\t%s\n"
		   "%-50s\t\t-----\t\t---------\n",
		   "Domain name", "Bytes", "Algorithm", "-----------");

	struct arg in[THREADS];
	pthread_t threads[THREADS];
	for(int i = 0; i < THREADS; i++) {
		in[i].zones = zones;
		in[i].linecount = linecount;
		in[i].start = i;
		pthread_create(&threads[i], NULL, request, &in[i]);
	}

	for(int i = 0; i < THREADS; i++) {
		pthread_join(threads[i], NULL);
	}

 exit:

	for(int i = 0; i < linecount; i++) {
		free(zones[i]);
	}
	free(zones);
	return 0;
}
