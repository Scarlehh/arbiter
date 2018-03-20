/*
 *  Simple example of a CUnit unit test.
 *
 *  This program (crudely) demonstrates a very simple "black box"
 *  test of the standard library functions fprintf() and fread().
 *  It uses suite initialization and cleanup functions to open
 *  and close a common temporary file used by the test functions.
 *  The test functions then write to and read from the temporary
 *  file in the course of testing the library functions.
 *
 *  The 2 test functions are added to a single CUnit suite, and
 *  then run using the CUnit Basic interface.  The output of the
 *  program (on CUnit version 2.0-2) is:
 *
 *           CUnit : A Unit testing framework for C.
 *           http://cunit.sourceforge.net/
 *
 *       Suite: Suite_1
 *         Test: test of fprintf() ... passed
 *         Test: test of fread() ... passed
 *
 *       --Run Summary: Type      Total     Ran  Passed  Failed
 *                      suites        1       1     n/a       0
 *                      tests         2       2       2       0
 *                      asserts       5       5       5       0
 */

#include "resolve.h"
#include "helper.h"
#include "CUnit/Basic.h"

#define CONFIG_FILE "testconfig.conf"

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

static isc_mem_t *mctx = NULL;
static isc_appctx_t *actx = NULL;
static isc_taskmgr_t *taskmgr = NULL;
static isc_socketmgr_t *socketmgr = NULL;
static isc_timermgr_t *timermgr = NULL;
static dns_client_t *client = NULL;
static isc_sockaddr_t *addr4 = NULL, *addr6 = NULL;

int dns_setup(void) {
	isc_result_t result;
	isc_lib_register();
	result = dns_lib_init();
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr, "dns_lib_init failed: %u\n", result);
		return -1;
	}

	result = create_dnsclient(&mctx, &actx, &taskmgr, &socketmgr,
										   &timermgr, &client, addr4, addr6);
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr, "create_dnsclient failed: %u\n", result);
		return -1;
	}

	return 0;
}

int dns_teardown(void) {
	dns_client_destroy(&client);

	if (taskmgr != NULL)
		isc_taskmgr_destroy(&taskmgr);
	if (timermgr != NULL)
		isc_timermgr_destroy(&timermgr);
	if (socketmgr != NULL)
		isc_socketmgr_destroy(&socketmgr);
	if (actx != NULL)
		isc_appctx_destroy(&actx);
	isc_mem_detach(&mctx);

	dns_lib_shutdown();

	return 0;
}

void test_setup_defnameserver(void) {
	isc_result_t result = set_defserver(mctx, client);
	CU_ASSERT(result == ISC_R_SUCCESS);

	result = dns_client_clearservers(client, dns_rdataclass_in, NULL);
	CU_ASSERT(result == ISC_R_SUCCESS);
}

void test_setup_successful_nameserver(void) {
	isc_result_t result = addserver(client, "127.0.0.1", "54", NULL);
	CU_ASSERT(result == ISC_R_SUCCESS);

	result = dns_client_clearservers(client, dns_rdataclass_in, NULL);
	CU_ASSERT(result == ISC_R_SUCCESS);
}

void test_setup_two_nameservers_should_exist_error(void) {
	isc_result_t result = set_defserver(mctx, client);
	CU_ASSERT(result == ISC_R_SUCCESS);
	result = addserver(client, "127.0.0.1", "54", NULL);
	CU_ASSERT(result == ISC_R_EXISTS);

	result = dns_client_clearservers(client, dns_rdataclass_in, NULL);
	CU_ASSERT(result == ISC_R_SUCCESS);
}

void test_setup_invalid_nameserver_ip_should_not_found(void) {
	isc_result_t result = addserver(client, "localhost", "54", NULL);
	CU_ASSERT(result == 8);
}


int mysql_setup(void) {
	struct dbconfig config;
	get_config(CONFIG_FILE, &config);
	MYSQL *con = mysql_init(NULL);

	if (con == NULL) {
		fprintf(stderr, "%s\n", mysql_error(con));
		return -1;
	}

	if (mysql_real_connect(con, "localhost", config.username, config.password,
						   config.dbname, 0, NULL, 0) == NULL) {
		goto fail;
	}

	if (mysql_query(con, "DROP TABLE IF EXISTS certificates")) {
		goto fail;
	}

	if (mysql_query(con, "CREATE TABLE certificates(domain VARCHAR(191) UNIQUE, cert BLOB)")) {
		goto fail;
	}

	if (mysql_query(con, "INSERT INTO certificates VALUES('.', 'FAKE CERT')")) {
		goto fail;
	}

	if (mysql_query(con, "INSERT INTO certificates VALUES('test.', NULL)")) {
		goto fail;
	}

	mysql_close(con);
	return 0;

 fail:
	fprintf(stderr, "%s\n", mysql_error(con));
	mysql_close(con);
	return -1;
}

int mysql_teardown(void) {
	struct dbconfig config;
	get_config(CONFIG_FILE, &config);
	MYSQL *con = mysql_init(NULL);

	if (con == NULL) {
		fprintf(stderr, "%s\n", mysql_error(con));
		return -1;
	}

	if (mysql_real_connect(con, "localhost", config.username, config.password,
						   config.dbname, 0, NULL, 0) == NULL) {
		goto fail;
	}

	if (mysql_query(con, "DROP TABLE IF EXISTS certificates")) {
		goto fail;
	}

	mysql_close(con);
	return 0;

 fail:
	fprintf(stderr, "%s\n", mysql_error(con));
	mysql_close(con);
	return -1;
}

void test_get_root_certificate(void) {
	MYSQL_ROW row;
	isc_result_t result = get_mysql_cert(CONFIG_FILE, ".", &row);
	CU_ASSERT(row != 0);
	CU_ASSERT(result == ISC_R_SUCCESS);
	CU_ASSERT(row[0] != NULL);
}

void test_get_nonexistent_domain(void) {
	MYSQL_ROW row;
	isc_result_t result = get_mysql_cert(CONFIG_FILE, "foo", &row);
	CU_ASSERT(row == 0);
	CU_ASSERT(result == ISC_R_SUCCESS);
}

void test_get_NULL_cert(void) {
	MYSQL_ROW row;
	isc_result_t result = get_mysql_cert(CONFIG_FILE, "test.", &row);
	CU_ASSERT(row != 0);
	CU_ASSERT(result == ISC_R_SUCCESS);
	CU_ASSERT(row[0] == NULL);
}


/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int main()
{
	CU_pSuite pSuite = NULL;

	// initialize the CUnit test registry
	if (CUE_SUCCESS != CU_initialize_registry())
		return CU_get_error();

	// Nameserver Suite
	pSuite = CU_add_suite("Setting up nameserver", dns_setup, dns_teardown);
	if (NULL == pSuite) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if ((NULL == CU_add_test(pSuite,
							 "Test setup default nameserver",
							 test_setup_defnameserver)) ||
		(NULL == CU_add_test(pSuite,
							 "Test setup external nameserver successfully",
							 test_setup_successful_nameserver)) ||
		(NULL == CU_add_test(pSuite,
							 "Test adding two nameservers gives exists error",
							 test_setup_two_nameservers_should_exist_error)) ||
		(NULL == CU_add_test(pSuite,
							 "Test nameserver with invalid ip gives not found",
							 test_setup_invalid_nameserver_ip_should_not_found))) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	// Database Suite
	pSuite = CU_add_suite("Retrieving certificates", mysql_setup, mysql_teardown);
	if (NULL == pSuite) {
		CU_cleanup_registry();
		return CU_get_error();
	}
	if ((NULL == CU_add_test(pSuite,
							 "Test get root certificate",
							 test_get_root_certificate)) ||
		(NULL == CU_add_test(pSuite,
							 "Test get certificate for nonexistent domain",
							 test_get_nonexistent_domain)) ||
		(NULL == CU_add_test(pSuite,
							 "Test get null certificate",
							 test_get_NULL_cert))) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	/* Run all tests using the CUnit Basic interface */
	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	CU_cleanup_registry();
	return CU_get_error();
}
