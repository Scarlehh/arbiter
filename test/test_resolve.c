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

#include <ldns/ldns.h>

#include <mysql/mysql.h>

#define CONFIG_FILE "testconfig.conf"

int verbosity = 5;

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
	char* cert;
	int result = get_mysql_cert(CONFIG_FILE, ".", &cert);
	CU_ASSERT(strcmp(cert, "FAKE CERT") == 0);
	CU_ASSERT(result == EXIT_SUCCESS);
	free(cert);
}

void test_get_nonexistent_domain(void) {
	char* cert;
	int result = get_mysql_cert(CONFIG_FILE, "foo", &cert);
	CU_ASSERT(result == EXIT_FAILURE);
}

void test_get_NULL_cert(void) {
	char* cert;
	int result = get_mysql_cert(CONFIG_FILE, "test.", &cert);
	CU_ASSERT(cert == NULL);
	CU_ASSERT(result == EXIT_SUCCESS);
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
