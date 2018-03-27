#include "resolver.h"

#include <ldns/ldns.h>
#include <ldns/resolver.h>
#include <ldns/rr.h>

extern int verbosity;

int
create_resolver(char* serv, ldns_resolver** res) {
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
query(ldns_resolver* res, char* domain, ldns_rr_type type, ldns_pkt* p) {
	if (verbosity >= 3) {
		printf("\nQuerying for: ");
		ldns_rdf_print(stdout, domain);
		printf("\n");
	}
	p = ldns_resolver_query(res, domain, type, LDNS_RR_CLASS_IN, LDNS_RD);
	if (verbosity >= 5) {
		if (p) {
			ldns_pkt_print(stdout, p);
		} else {
			fprintf(stdout, "No Packet Received from ldns_resolver_query()\n");
		}
	}
}
