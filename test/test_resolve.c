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
#include "CUnit/Basic.h"

int setup(void)
{
	return 0;
}

int teardown(void)
{
	return 0;
}

void test(void)
{
	CU_PASS("Test!")
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

	// add a suite to the registry
	pSuite = CU_add_suite("Suite_1", setup, teardown);
	if (NULL == pSuite) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	// add the tests to the suite
	if (NULL == CU_add_test(pSuite, "testing", test))
		{
			CU_cleanup_registry();
			return CU_get_error();
		}

	/* Run all tests using the CUnit Basic interface */
	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	CU_cleanup_registry();
	return CU_get_error();
}
