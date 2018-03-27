#include "resolver.h"
#include "helper.h"

#include <ldns/ldns.h>
#include <ldns/resolver.h>
#include <ldns/rr.h>

#define CONFIG_FILE "config.conf"
#define MAXBUF 1024

extern int verbosity;

int
create_resolver(ldns_resolver** res, char* serv) {
	ldns_status status;

	ldns_rdf* serv_rdf;
	ldns_resolver *cmdline_res;
	ldns_rr_list *cmdline_rr_list;
	ldns_rdf *cmdline_dname;

	if(!serv) {
		if (ldns_resolver_new_frm_file(res, NULL) != LDNS_STATUS_OK) {
			fprintf(stderr, "%s", "Could not create resolver obj");
			return EXIT_FAILURE;
		}
	} else {
		*res = ldns_resolver_new();
		if (!(*res) || strlen(serv) <= 0) {
			return EXIT_FAILURE;
		}
		/* add the nameserver */
		serv_rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, serv);
		if (!serv_rdf) {
			/* maybe ip6 */
			serv_rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, serv);
		}
		if (!serv_rdf) {
			/* try to resolv the name if possible */
			status = ldns_resolver_new_frm_file(&cmdline_res, NULL);

			if (status != LDNS_STATUS_OK) {
				fprintf(stderr, "%s", "@server ip could not be converted");
				return EXIT_FAILURE;
			}

			cmdline_dname = ldns_dname_new_frm_str(serv);
			cmdline_rr_list = ldns_get_rr_list_addr_by_name(
															cmdline_res,
															cmdline_dname,
															LDNS_RR_CLASS_IN,
															0);
			ldns_rdf_deep_free(cmdline_dname);
			ldns_resolver_deep_free(cmdline_res);
			if (!cmdline_rr_list) {
				fprintf(stderr, "%s %s", "could not find any address for the name: ", serv);
				return EXIT_FAILURE;
			} else {
				if (ldns_resolver_push_nameserver_rr_list(
														  *res,
														  cmdline_rr_list
														  ) != LDNS_STATUS_OK) {
					fprintf(stderr, "%s", "pushing nameserver");
					ldns_rr_list_deep_free(cmdline_rr_list);
					return EXIT_FAILURE;
				}
				ldns_rr_list_deep_free(cmdline_rr_list);
			}
		} else {
			if (ldns_resolver_push_nameserver(*res, serv_rdf) != LDNS_STATUS_OK) {
				fprintf(stderr, "%s", "pushing nameserver");
				return EXIT_FAILURE;
			} else {
				ldns_rdf_deep_free(serv_rdf);
			}
		}
	}
	return EXIT_SUCCESS;
}

int
query(ldns_pkt** p, ldns_resolver* res, char* domain, ldns_rr_type type) {
	if (verbosity >= 3) {
		printf("\nQuerying for: ");
		ldns_rdf_print(stdout, domain);
		printf("\n");
	}
	*p = ldns_resolver_query(res, domain, type, LDNS_RR_CLASS_IN, LDNS_RD);
	if (verbosity >= 5) {
		if (*p) {
			ldns_pkt_print(stdout, *p);
		} else {
			fprintf(stdout, "No Packet Received from ldns_resolver_query()\n");
		}
	}
}

int
get_key(char** keystr, char* keynamestr) {
	char* cert;
	int result = get_mysql_cert(CONFIG_FILE, keynamestr, &cert);
	if (result != EXIT_SUCCESS) {
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
		return EXIT_FAILURE;
	}

	// Get public key from certificate
	EVP_PKEY* pkey = X509_get_pubkey(certX509);
	X509_free(certX509);
	BIO_free(cert_bio);
	if (!pkey) {
		fprintf(stderr, "failed to extract public key from certificate\n");
		return EXIT_FAILURE;
	}

	// Convert public key to base64 encoding
	BIO* key_bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(key_bio, pkey);
	char* p;
	int read_size = (int) BIO_get_mem_data(key_bio, &p);
	EVP_PKEY_free(pkey);
	if (read_size < 1 || !p) {
		BIO_free(key_bio);
		fprintf(stderr, "failed to read public key\n");
		return EXIT_FAILURE;
	}

	// Copy public key
	const char* KEY_START = "-----BEGIN PUBLIC KEY-----\n";
	const char* KEY_END = "-----END PUBLIC KEY-----";
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
		result = EXIT_SUCCESS;
	} else {
		fprintf(stderr, "failed to extract base64 from labels\n");
		result = EXIT_FAILURE;
	}
	BIO_free(key_bio);

	return EXIT_SUCCESS;
}

int
create_verifier(ldns_dnssec_data_chain** chain, ldns_dnssec_trust_tree** tree,
				ldns_resolver* res, ldns_rr_list* rrlist, ldns_pkt* pkt) {
	*chain = ldns_dnssec_build_data_chain(res, NULL, rrlist, pkt, NULL);
	if (!chain) {
		fprintf(stderr, "Couldn't create DNSSEC data chain\n");
		return EXIT_FAILURE;
	} else if (verbosity >= 4) {
		printf("\n\nDNSSEC Data Chain:\n");
		ldns_dnssec_data_chain_print(stdout, *chain);
	}

	*tree = ldns_dnssec_derive_trust_tree(*chain, NULL);
	if (!tree) {
		fprintf(stderr, "Couldn't create DNSSEC trust tree\n");
		return EXIT_FAILURE;
	} else if (verbosity >= 2) {
		printf("\n\nDNSSEC Trust tree:\n");
		ldns_dnssec_trust_tree_print(stdout, *tree, 0, true);
	}
	return EXIT_SUCCESS;
}

int
verify(ldns_dnssec_trust_tree* tree, ldns_rr_list* trustedkeys) {
	if (ldns_rr_list_rr_count(trustedkeys) > 0) {
		ldns_status tree_result =
			ldns_dnssec_trust_tree_contains_keys(tree, trustedkeys);

		if (tree_result == LDNS_STATUS_DNSSEC_EXISTENCE_DENIED) {
			if (verbosity >= 1) {
				printf("Existence denied or verifiably insecure\n");
			}
			return EXIT_FAILURE;
		} else if (tree_result != LDNS_STATUS_OK) {
			if (verbosity >= 1) {
				printf("No trusted keys found in tree: first error was: %s\n", ldns_get_errorstr_by_id(tree_result));
			}
			return EXIT_FAILURE;
		} else {
			printf("Chain verified.\n");
			return EXIT_SUCCESS;
		}
	}
	if (verbosity >= 0) {
		printf("You have not provided any trusted keys.\n");
	}
	return EXIT_FAILURE;
}
