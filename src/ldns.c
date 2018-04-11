#include "resolve.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include <ldns/ldns.h>

#define LDNS_RESOLV_INETANY		0
#define LDNS_RESOLV_INET		1
#define LDNS_RESOLV_INET6		2

int verbosity = 0;

void
show_time(struct timeval start, struct timeval end) {
	int s = end.tv_sec - start.tv_sec;
	int us = end.tv_usec - start.tv_usec;
	if (us < 0) {
		s -= 1;
		us += 1000000;
	}
	printf("\nTime taken: %d us\n", (s*1000000)+us);
}

static int
usage(FILE *fp, char *prog) {
	fprintf(fp, "%s [options] domain\n", prog);
	fprintf(fp, "  print out the owner names for domain and the record types for those names\n");
	fprintf(fp, "OPTIONS:\n");
	fprintf(fp, "-4\t\tonly use IPv4\n");
	fprintf(fp, "-6\t\tonly use IPv6\n");
	fprintf(fp, "-val-chain [-c] \t\tValidate DNSSEC chain [and check database for keys]\n");
	fprintf(fp, "-val-RR [-t <rrtype>] \t\tValidate requested RR [and additional records]\n");
	fprintf(fp, "-t <rrtype>\t\tLook up this record\n");
	fprintf(fp, "-k <key origin> -K <key string> [-KSK]\t\tAdd key to trusted keys\n");
	fprintf(fp, "-v <verbosity>\t\tVerbosity level [1-5]\n");
	fprintf(fp, "-version\tShow version and exit\n");
	fprintf(fp, "@<nameserver>\t\tUse this nameserver\n");
	return 0;
}

int
main(int argc, char *argv[]) {
	int result;
	uint8_t fam = LDNS_RESOLV_INETANY;
	int check_database = 0;
	int val_chain = 0;
	int val_RR = 0;

	char *arg_end_ptr = NULL;
	char *serv = NULL;
	const char* arg_domain = NULL;

	ldns_rdf *domain = NULL;

	ldns_rr_type rtype = LDNS_RR_TYPE_A;
	ldns_rr_type rtype_additional = NULL;

	ldns_rr_list* rrset_trustedkeys = ldns_rr_list_new();

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
			} else if (strcmp("-val-chain", argv[i]) == 0) {
				val_chain = 1;
				if (i + 1 < argc) {
					if (strncmp(argv[i + 1], "-c", 3) == 0) {
						check_database = 1;
						i++;
					}
				}
			} else if (strcmp("-val-RR", argv[i]) == 0) {
				val_RR = 1;
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
			} else if (strncmp(argv[i], "-k", 3) == 0) {
				if (i + 1 < argc) {
					char* origin = argv[i + 1];
					i+=2;
					if ((strncmp(argv[i], "-K", 3) == 0) && (i + 1 < argc)) {
						char* key = argv[i + 1];
						int ksk = 0;
						if (strncmp(argv[i + 2], "-KSK", 5) == 0) {
							ksk = 1;
							i++;
						}
						ldns_rr* rr_trustedkey;
						result = trustedkey_fromkey(&rr_trustedkey, key,
													origin, ksk);
						if (result != LDNS_STATUS_OK)
							goto exit;

						result = addto_trustedkeys(rrset_trustedkeys,
												   rr_trustedkey);
						if (result != LDNS_STATUS_OK)
							goto exit;
					} else {
						printf("Missing argument for -K\n");
						exit(1);
					}
				} else {
					printf("Missing argument for -k\n");
					exit(1);
				}
				i++;
			} else if (strncmp(argv[i], "-K", 3) == 0) {
				printf("Missing argument for -k\n");
				exit(1);
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
	result = create_resolver(&res, serv);
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
		fprintf(stderr, "No records for given type\n");
		result = 3;
		ldns_pkt_free(pkt);

		ldns_rdf_deep_free(domain);
		ldns_resolver_deep_free(res);
		goto exit;
	}

	// Check requested RR is OK
	if (val_RR) {
		struct timeval start, end;
		gettimeofday(&start, NULL);
		verify_rr(rrset,
				  ldns_pkt_rr_list_by_type(pkt, LDNS_RR_TYPE_RRSIG,
										   LDNS_SECTION_ANSWER),
				  arg_domain);
		gettimeofday(&end, NULL);
		show_time(start, end);
	}

	// Populate trusted key list from database
	if (check_database) {
		result = populate_trustedkeys(rrset_trustedkeys, arg_domain);
		if (result != LDNS_STATUS_OK)
			goto cleanup;
	}

	// Verify DNSSEC tree valid
	if (val_chain) {
		ldns_dnssec_data_chain* chain;
		ldns_dnssec_trust_tree* tree;
		struct timeval start, end;
		gettimeofday(&start, NULL);
		result = verify_trust(&chain, &tree, res, rrset, pkt);

		// Check trusted keys exist in chain of trust
		if (result == LDNS_STATUS_OK) {
			check_trustedkeys(tree, rrset_trustedkeys);
			gettimeofday(&end, NULL);
			show_time(start, end);
		}
		ldns_dnssec_trust_tree_free(tree);
		ldns_dnssec_data_chain_deep_free(chain);
	}

	// Cleanup
 cleanup:
	ldns_rr_list_deep_free(rrset);
	ldns_pkt_free(pkt);

	ldns_rdf_deep_free(domain);
	ldns_resolver_deep_free(res);
 exit:
	ldns_rr_list_deep_free(rrset_trustedkeys);

	return result;
}
