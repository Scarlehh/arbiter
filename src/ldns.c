#include "resolver.h"

#include <stdio.h>
#include <stdlib.h>

#include <ldns/ldns.h>

#define LDNS_RESOLV_INETANY		0
#define LDNS_RESOLV_INET		1
#define LDNS_RESOLV_INET6		2

int verbosity = 0;

static int
usage(FILE *fp, char *prog) {
	fprintf(fp, "%s [options] domain\n", prog);
	fprintf(fp, "  print out the owner names for domain and the record types for those names\n");
	fprintf(fp, "OPTIONS:\n");
	fprintf(fp, "-4\t\tonly use IPv4\n");
	fprintf(fp, "-6\t\tonly use IPv6\n");
	fprintf(fp, "-f\t\tfull; get all rrsets instead of only a list of names and types\n");
	fprintf(fp, "-t <rrtype>\t\tLook up this record\n");
	fprintf(fp, "-v <verbosity>\t\tVerbosity level [1-5]\n");
	fprintf(fp, "-version\tShow version and exit\n");
	fprintf(fp, "@<nameserver>\t\tUse this nameserver\n");
	return 0;
}

int
main(int argc, char *argv[]) {
	int full = 0;
	uint8_t fam = LDNS_RESOLV_INETANY;

	char *arg_end_ptr = NULL;
	char *serv = NULL;
	const char* arg_domain = NULL;

	ldns_rdf *domain = NULL;
	ldns_rdf *startpoint = NULL;

	ldns_rr_type rtype = LDNS_RR_TYPE_A;

	if (argc < 2) {
		usage(stdout, argv[0]);
		exit(EXIT_FAILURE);
	} else {
		for (int i = 1; i < argc; i++) {
			if (strncmp(argv[i], "-4", 3) == 0) {
				if (fam != LDNS_RESOLV_INETANY) {
					fprintf(stderr, "You can only specify one of -4 or -6\n");
					exit(1);
				}
				fam = LDNS_RESOLV_INET;
			} else if (strncmp(argv[i], "-6", 3) == 0) {
				if (fam != LDNS_RESOLV_INETANY) {
					fprintf(stderr, "You can only specify one of -4 or -6\n");
					exit(1);
				}
				fam = LDNS_RESOLV_INET6;
			} else if (strncmp(argv[i], "-f", 3) == 0) {
				full = true;
			} else if (strncmp(argv[i], "-t", 3) == 0) {
				if (i + 1 < argc) {
					if (!strcmp(argv[i + 1], "A")) {
						rtype = LDNS_RR_TYPE_A;
					} else if (!strcmp(argv[i + 1], "NS")) {
						rtype = LDNS_RR_TYPE_NS;
					} else if (!strcmp(argv[i + 1], "CNAME")) {
						rtype = LDNS_RR_TYPE_CNAME;
					} else if (!strcmp(argv[i + 1], "SOA")) {
						rtype = LDNS_RR_TYPE_SOA;
					} else if (!strcmp(argv[i + 1], "DS")) {
						rtype = LDNS_RR_TYPE_DS;
					} else if (!strcmp(argv[i + 1], "DNSKEY")) {
						rtype = LDNS_RR_TYPE_DNSKEY;
					} else {
						fprintf(stderr, "RRtype not supported\n");
						exit(1);
					}
				} else {
					printf("Missing argument for -t\n");
					exit(1);
				}
				i++;
			} else if (strncmp(argv[i], "-v", 3) == 0) {
				if (i + 1 < argc) {
					verbosity = strtol(argv[i+1], &arg_end_ptr, 10);
					if (*arg_end_ptr != '\0') {
						printf("Bad argument for -v: %s\n", argv[i+1]);
						exit(1);
					}
				} else {
					printf("Missing argument for -v\n");
					exit(1);
				}
				i++;
			} else if (strcmp("-version", argv[i]) == 0) {
				printf("dns zone walker, version %s (ldns version %s)\n", LDNS_VERSION, ldns_version());
				goto exit;
			} else {
				if (argv[i][0] == '@') {
					if (strlen(argv[i]) == 1) {
						if (i + 1 < argc) {
							serv = argv[i + 1];
							i++;
						} else {
							printf("Missing argument for -s\n");
							exit(1);
						}
					} else {
						serv = argv[i] + 1;
					}
				} else {
					if (i < argc) {
						if (!domain) {
							/* create a rdf from the command line arg */
							arg_domain = argv[i];
							domain = ldns_dname_new_frm_str(arg_domain);
							if (!domain) {
								usage(stdout, argv[0]);
								exit(1);
							}
						} else {
							printf("One domain at a time please\n");
							exit(1);
						}
					} else {
						printf("No domain given to walk\n");
						exit(1);
					}
				}
			}
		}
	}
	if (!domain) {
		printf("Missing argument\n");
		exit(1);
	}

	// Create resolver
	ldns_resolver *res;
	int result = create_resolver(&res, serv);
	if (result != EXIT_SUCCESS)
		goto exit;

	// Configure resolver
	ldns_resolver_set_dnssec(res, true);
	ldns_resolver_set_dnssec_cd(res, true);
	ldns_resolver_set_ip6(res, fam);
	if (!res) {
		result = 2;
		goto exit;
	}

	// Make query
	ldns_pkt* pkt;
	query(&pkt, res, domain, rtype);
	ldns_rr_list* rrset =
		ldns_pkt_rr_list_by_type(pkt, rtype, LDNS_SECTION_ANSWER);
	if (!rrset) {
		rrset = ldns_pkt_rr_list_by_type(pkt, rtype,
										 LDNS_SECTION_AUTHORITY);
		if (!rrset) {
			fprintf(stderr, "No records for given type\n");
			result = 3;
			goto exit;
		}
	}

	// Create dnssec trust tree
	ldns_dnssec_data_chain* chain;
	ldns_dnssec_trust_tree* tree;
	create_verifier(&chain, &tree, res, rrset, pkt);

	// Populate trusted key list
	ldns_rr_list* rrset_trustedkeys = ldns_rr_list_new();
	populate_trustedkeys(rrset_trustedkeys, arg_domain);

	// Verify chain of trust
	verify(tree, rrset_trustedkeys);

	// Cleanup
	ldns_rr_list_deep_free(rrset_trustedkeys);

	ldns_dnssec_trust_tree_free(tree);
	ldns_dnssec_data_chain_deep_free(chain);

	ldns_rr_list_deep_free(rrset);
	ldns_pkt_free(pkt);

	ldns_rdf_deep_free(domain);
	ldns_resolver_deep_free(res);
 exit:
	return result;
}
