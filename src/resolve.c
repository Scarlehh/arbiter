#include "resolve.h"
#include "helper.h"

#include <ldns/ldns.h>

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
			return LDNS_STATUS_ERR;
		}
	} else {
		*res = ldns_resolver_new();
		if (!(*res) || strlen(serv) <= 0) {
			return LDNS_STATUS_ERR;
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
				return status;
			}

			cmdline_dname = ldns_dname_new_frm_str(serv);
			cmdline_rr_list = ldns_get_rr_list_addr_by_name(cmdline_res,
															cmdline_dname,
															LDNS_RR_CLASS_IN,
															0);
			ldns_rdf_deep_free(cmdline_dname);
			ldns_resolver_deep_free(cmdline_res);
			if (!cmdline_rr_list) {
				fprintf(stderr, "%s %s", "could not find any address for the name: ", serv);
				return LDNS_STATUS_ERR;
			} else {
				if (ldns_resolver_push_nameserver_rr_list(
														  *res,
														  cmdline_rr_list
														  ) != LDNS_STATUS_OK) {
					fprintf(stderr, "%s", "pushing nameserver");
					ldns_rr_list_deep_free(cmdline_rr_list);
					return LDNS_STATUS_ERR;
				}
				ldns_rr_list_deep_free(cmdline_rr_list);
			}
		} else {
			if (ldns_resolver_push_nameserver(*res, serv_rdf) != LDNS_STATUS_OK) {
				fprintf(stderr, "%s", "pushing nameserver");
				return LDNS_STATUS_ERR;
			} else {
				ldns_rdf_deep_free(serv_rdf);
			}
		}
	}
	return LDNS_STATUS_OK;
}

int
query(ldns_pkt** p, ldns_resolver* res, char* domain, ldns_rr_type type) {
	if (verbosity >= 2) {
		printf("\nQuerying for: ");
		ldns_rdf_print(stdout, domain);
		printf("\n");
	}
	*p = ldns_resolver_query(res, domain, type, LDNS_RR_CLASS_IN, LDNS_RD);
	if (verbosity >= 3) {
		if (*p) {
			ldns_pkt_print(stdout, *p);
		} else {
			printf("No Packet Received from ldns_resolver_query()\n");
		}
	}
	return LDNS_STATUS_OK;
}

int
get_key(char** keystr, char* keynamestr, int ksk) {
	char* cert;
	int result = get_mysql_cert(CONFIG_FILE, keynamestr, &cert, ksk);
	if (result != LDNS_STATUS_OK) {
		if (verbosity >= 2)
			printf("Failed to get certificate %s %s from the database: %u\n",
					keynamestr, (ksk ? "KSK" : "ZSK"), result);
		return result;
	}

	// Convert MYSQL query to X509
	BIO* cert_bio = BIO_new(BIO_s_mem());
	BIO_write(cert_bio, cert, strlen(cert));
	X509* certX509 = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
	free(cert);
	if (!certX509) {
		fprintf(stderr, "Failed to parse certificate in memory\n");
		return LDNS_STATUS_SSL_ERR;
	}

	// Get public key from certificate
	EVP_PKEY* pkey = X509_get_pubkey(certX509);
	X509_free(certX509);
	BIO_free(cert_bio);
	if (!pkey) {
		fprintf(stderr, "Failed to extract public key from certificate\n");
		return LDNS_STATUS_SSL_ERR;
	}

	// Convert public key to base64 encoding
	BIO* key_bio = BIO_new(BIO_s_mem());
	PEM_write_bio_PUBKEY(key_bio, pkey);
	char* p;
	int read_size = (int) BIO_get_mem_data(key_bio, &p);
	EVP_PKEY_free(pkey);
	if (read_size < 1 || !p) {
		BIO_free(key_bio);
		fprintf(stderr, "Failed to read public key\n");
		return LDNS_STATUS_SSL_ERR;
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
		result = LDNS_STATUS_OK;
	} else {
		fprintf(stderr, "Failed to extract base64 from labels\n");
		result = LDNS_STATUS_INVALID_B64;
	}
	BIO_free(key_bio);

	return result;
}

int
verify_trust(ldns_dnssec_data_chain** chain, ldns_dnssec_trust_tree** tree,
			 ldns_resolver* res, ldns_rr_list* rrlist, ldns_pkt* pkt) {
	printf(
		   "\n-------------------------\n"
		   "Verifying Trust Chain\n"
		   "-------------------------\n");
	*chain = ldns_dnssec_build_data_chain(res, NULL, rrlist, pkt, NULL);
	if (!(*chain)) {
		fprintf(stderr, "Couldn't create DNSSEC data chain\n");
		return LDNS_STATUS_ERR;
	} else if (verbosity >= 4) {
		printf("\n\nDNSSEC Data Chain:\n");
		ldns_dnssec_data_chain_print(stdout, *chain);
	}

	*tree = ldns_dnssec_derive_trust_tree(*chain, NULL);
	if (!(*tree)) {
		fprintf(stderr, "Couldn't create DNSSEC trust tree\n");
		return LDNS_STATUS_ERR;
	} else if (verbosity >= 0) {
		printf("DNSSEC Trust tree:\n");
		ldns_dnssec_trust_tree_print(stdout, *tree, 0, true);
		printf("\n");
	}
	return LDNS_STATUS_OK;
}

int
check_trustedkeys(ldns_dnssec_trust_tree* tree, ldns_rr_list* trustedkeys) {
	printf(
		   "\n-------------------------\n"
		   "Verifying Keys Trusted\n"
		   "-------------------------\n");
	if (ldns_rr_list_rr_count(trustedkeys) > 0) {
		ldns_status tree_result =
			ldns_dnssec_trust_tree_contains_keys(tree, trustedkeys);

		if (tree_result == LDNS_STATUS_DNSSEC_EXISTENCE_DENIED) {
			if (verbosity >= 0) {
				printf("Existence denied or verifiably insecure\n");
			}
			return LDNS_STATUS_OK;
		} else if (tree_result != LDNS_STATUS_OK) {
			if (verbosity >= 0) {
				printf("No trusted keys found in tree: first error was: %s\n", ldns_get_errorstr_by_id(tree_result));
			}
			return LDNS_STATUS_CRYPTO_NO_TRUSTED_DNSKEY;
		} else {
			if (verbosity >= 0)
				printf("Chain verified.\n\n");
			return LDNS_STATUS_OK;
		}
	}
	if (verbosity >= 0)
		printf("You have not provided any trusted keys.\n");

	return LDNS_STATUS_CRYPTO_NO_TRUSTED_DNSKEY;
}

int
trustedkey_fromkey(ldns_rr** rr_trustedkey, char* key, char* domain,
				   int ksk) {
	char* rr_str;
	if (ksk)
		rr_str = " IN DNSKEY 257 3 13 ";
	else
		rr_str = " IN DNSKEY 256 3 13 ";
	int len_dnskey = strlen(key) + strlen(domain) + strlen(rr_str) + 1;
	const char* dnskey_str = malloc(sizeof(char) * len_dnskey);
	snprintf(dnskey_str, len_dnskey, "%s%s%s", domain, rr_str, key);
	if (verbosity >= 2) {
		fprintf(stderr, "\nDNSKEY string: %s\n\n", dnskey_str);
	}

	int result = ldns_rr_new_frm_str(rr_trustedkey, dnskey_str, 0, NULL, NULL);
	free(dnskey_str);
	if (result != LDNS_STATUS_OK) {
		fprintf(stderr, "Couldn't make trusted DNSKEY record from key: %d\n", result);
		return result;
	}

	return LDNS_STATUS_OK;
}

int
addto_trustedkeys(ldns_rr_list* rrset_trustedkeys, ldns_rr* rr_trustedkey) {
	int result = ldns_rr_list_push_rr(rrset_trustedkeys, rr_trustedkey);
	if (result != true) {
		fprintf(stderr, "Couldn't push resource record to trusted key set: %d\n", result);
	}
	return LDNS_STATUS_OK;
}

int
populate_trustedkeys(ldns_rr_list* rrset_trustedkeys, char* domain) {
	int result;
	char* p = domain;
	while(p != NULL) {
		char* key = NULL;
		for(int i = 0; i <= 1; i++) {
			get_key(&key, p, i);
			if (key != NULL) {
				if (verbosity >= 4)
					fprintf(stderr, "Key for %s is %s\n", p, key);

				ldns_rr* rr_trustedkey;
				result = trustedkey_fromkey(&rr_trustedkey, key+36, p, i);
				if (result == LDNS_STATUS_OK) {
					addto_trustedkeys(rrset_trustedkeys, rr_trustedkey);
				}
				free(key);
			}
		}
		p = strstr(p+1, ".");
		// Check root
		if (p != NULL && strlen(p) > 1) {
			p+=1;
		}
	}
	return LDNS_STATUS_OK;
}

int
verify_rr(ldns_rr_list* rrset, ldns_pkt* pkt, char* domain) {
	printf(
		   "\n-------------------------\n"
		   "Verifying Resource Record\n"
		   "-------------------------\n");
	ldns_rr_list* rrsig =
		ldns_pkt_rr_list_by_type(pkt, LDNS_RR_TYPE_RRSIG, LDNS_SECTION_ANSWER);
	if (!rrsig) {
		printf("No resource record signature; DNSSEC enabled?\n");
		return LDNS_STATUS_CRYPTO_NO_RRSIG;
	}
	if (verbosity >= 1)
		printf("Found %d RRSIG\n", ldns_rr_list_rr_count(rrsig));

	char* zsk;
	char* ksk;
	int result = get_key(&zsk, domain, false);
	if (result != LDNS_STATUS_OK)
		zsk = NULL;
	result = get_key(&ksk, domain, true);
	if (result != LDNS_STATUS_OK)
		ksk = NULL;

	if (zsk == NULL && ksk == NULL) {
		if (verbosity >= 0)
			printf("No keys available in database\n");
		return LDNS_STATUS_CRYPTO_NO_TRUSTED_DNSKEY;
	}

	ldns_rr* trustedzsk = NULL;
	if (zsk != NULL) {
		fprintf(stderr, "Test\n");
		result = trustedkey_fromkey(&trustedzsk, zsk+36, domain, false);
		free(zsk);
		if (result != LDNS_STATUS_OK) {
			return result;
		}
	}
	ldns_rr* trustedksk = NULL;
	if (ksk) {
		result = trustedkey_fromkey(&trustedksk, ksk+36, domain, true);
		free(ksk);
		if (result != LDNS_STATUS_OK) {
			return result;
		}
	}

	for(int i = 0; i < ldns_rr_list_rr_count(rrsig); i++) {
		if (verbosity >= 1)
			printf("\nTrying to verify with zsk...");

		if (trustedzsk) {
			result = ldns_verify_rrsig(rrset,
									   ldns_rr_list_rr(rrsig, i),
									   trustedzsk);
			if (verbosity >= 1) {
				if (result == LDNS_STATUS_OK)
					printf("success\n");
				else
					printf("failure\n");
			}
		} else {
			result = LDNS_STATUS_CRYPTO_NO_TRUSTED_DNSKEY;
			printf("no zsk\n");
		}

		// Try KSK if ZSK fails
		if (result != LDNS_STATUS_OK) {
			if (verbosity >= 1)
				printf("Trying to verify with ksk...");

			if (trustedksk) {
				result = ldns_verify_rrsig(rrset,
										   ldns_rr_list_rr(rrsig, i),
										   trustedksk);
				if (verbosity >= 1) {
					if (result == LDNS_STATUS_OK)
						printf("success\n");
					else
						printf("failure\n");
				}
			} else {
				result = LDNS_STATUS_CRYPTO_NO_TRUSTED_DNSKEY;
				printf("no ksk\n");
			}
		}

		if (verbosity >= 0)
			printf("Verification result of RRSIG %d for %s: %s\n\n", i, domain,
				   ldns_get_errorstr_by_id(result));
	}
	return result;
}
