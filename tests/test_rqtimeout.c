/*
 * Phoenix-RTOS
 *
 * POSIX server - deferred request timeout unit tests
 *
 * Copyright 2026 Phoenix Systems
 * Author: Adam Greloch
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <string.h>

#include <unity_fixture.h>

#include "../posixsrv.c"


int pipe_init(void)
{
	return -ENOSYS;
}


int pty_init(void)
{
	return -ENOSYS;
}


int event_init(unsigned *port)
{
	return -ENOSYS;
}


int special_init(void)
{
	return -ENOSYS;
}


int tmpfile_init(void)
{
	return -ENOSYS;
}


int semaphore_init(void)
{
	return -ENOSYS;
}


#define TEST_REQUESTS 8


static request_t test_requests[TEST_REQUESTS];


static request_t *test_minimum(void)
{
	return lib_treeof(request_t, linkage, lib_rbMinimum(posixsrv_common.timeout.tree.root));
}


static int test_armed(request_t *r)
{
	return lib_rbFind(&posixsrv_common.timeout.tree, &r->linkage) == &r->linkage;
}


TEST_GROUP(rq_timeout);


TEST_SETUP(rq_timeout)
{
	size_t i;

	/* posixsrv_init() is never run here, so stand the timeout tree up by hand */
	memset(test_requests, 0, sizeof(test_requests));
	for (i = 0; i < TEST_REQUESTS; i++) {
		test_requests[i].timeoutState = rq_timeoutIdle;
		test_requests[i].rid = (msg_rid_t)i;
	}

	lib_rbInit(&posixsrv_common.timeout.tree, rq_cmp, NULL);
	TEST_ASSERT_GREATER_OR_EQUAL_INT(0, mutexCreate(&posixsrv_common.timeout.lock));
	TEST_ASSERT_GREATER_OR_EQUAL_INT(0, condCreate(&posixsrv_common.timeout.cond));
}


TEST_TEAR_DOWN(rq_timeout)
{
	resourceDestroy(posixsrv_common.timeout.cond);
	resourceDestroy(posixsrv_common.timeout.lock);
}


TEST(rq_timeout, minimum_is_the_earliest_deadline)
{
	static const time_t deadlines[] = { 5000, 1000, 9000, 3000 };
	size_t i;

	for (i = 0; i < sizeof(deadlines) / sizeof(deadlines[0]); i++) {
		rq_timeoutAt(&test_requests[i], deadlines[i]);
		TEST_ASSERT_EQUAL_INT(rq_timeoutArmed, test_requests[i].timeoutState);
	}

	TEST_ASSERT_EQUAL_PTR(&test_requests[1], test_minimum());
}


TEST(rq_timeout, requests_leave_in_deadline_order)
{
	static const time_t deadlines[] = { 5000, 1000, 9000, 3000, 7000 };
	const size_t count = sizeof(deadlines) / sizeof(deadlines[0]);
	time_t previous = 0;
	request_t *r;
	size_t i;

	for (i = 0; i < count; i++) {
		rq_timeoutAt(&test_requests[i], deadlines[i]);
	}

	for (i = 0; i < count; i++) {
		r = test_minimum();
		TEST_ASSERT_NOT_NULL(r);
		TEST_ASSERT_TRUE(r->wakeup > previous);
		previous = r->wakeup;

		TEST_ASSERT_EQUAL_INT(1, rq_timeoutCancel(r));
	}

	TEST_ASSERT_NULL(posixsrv_common.timeout.tree.root);
}


TEST(rq_timeout, equal_deadlines_are_all_armed)
{
	const size_t count = 4;
	size_t i;

	for (i = 0; i < count; i++) {
		rq_timeoutAt(&test_requests[i], 4000);
		TEST_ASSERT_EQUAL_INT(rq_timeoutArmed, test_requests[i].timeoutState);
	}

	/* every one of them is in the tree, not just the first */
	for (i = 0; i < count; i++) {
		TEST_ASSERT_TRUE(test_armed(&test_requests[i]));
	}

	for (i = 0; i < count; i++) {
		TEST_ASSERT_NOT_NULL(test_minimum());
		TEST_ASSERT_EQUAL_INT(1, rq_timeoutCancel(test_minimum()));
	}

	TEST_ASSERT_NULL(posixsrv_common.timeout.tree.root);
}


/* a request armed relatively is ordered against absolute deadlines, not appended */
TEST(rq_timeout, relative_and_absolute_deadlines_share_one_order)
{
	time_t now;

	gettime(&now, NULL);

	rq_timeoutAt(&test_requests[0], now + 10 * 1000 * 1000);
	rq_timeout(&test_requests[1], 1000);

	TEST_ASSERT_EQUAL_PTR(&test_requests[1], test_minimum());
}


/* the claim rq_timeoutCancel() reports decides who completes the request */
TEST(rq_timeout, cancel_reports_ownership)
{
	/* never armed - nothing to cancel, the caller owns it */
	TEST_ASSERT_EQUAL_INT(1, rq_timeoutCancel(&test_requests[0]));

	rq_timeoutAt(&test_requests[1], 1000);
	TEST_ASSERT_EQUAL_INT(1, rq_timeoutCancel(&test_requests[1]));
	TEST_ASSERT_EQUAL_INT(rq_timeoutIdle, test_requests[1].timeoutState);
	TEST_ASSERT_FALSE(test_armed(&test_requests[1]));

	/* already claimed by the timeout thread - not ours any more */
	test_requests[2].timeoutState = rq_timeoutFired;
	TEST_ASSERT_EQUAL_INT(0, rq_timeoutCancel(&test_requests[2]));
}


TEST(rq_timeout, arming_twice_leaves_the_tree_intact)
{
	rq_timeoutAt(&test_requests[0], 5000);
	rq_timeoutAt(&test_requests[1], 1000);

	/* try to re-arm the request that is already sorted at 5000. Should fail. */
	rq_timeoutAt(&test_requests[0], 100);

	TEST_ASSERT_TRUE(test_requests[0].wakeup == 5000);
	TEST_ASSERT_EQUAL_INT(rq_timeoutArmed, test_requests[0].timeoutState);

	/* the ordering still holds, so both requests are still reachable */
	TEST_ASSERT_TRUE(test_armed(&test_requests[0]));
	TEST_ASSERT_TRUE(test_armed(&test_requests[1]));
	TEST_ASSERT_EQUAL_PTR(&test_requests[1], test_minimum());

	TEST_ASSERT_EQUAL_INT(1, rq_timeoutCancel(&test_requests[1]));
	TEST_ASSERT_EQUAL_PTR(&test_requests[0], test_minimum());
	TEST_ASSERT_EQUAL_INT(1, rq_timeoutCancel(&test_requests[0]));

	TEST_ASSERT_NULL(posixsrv_common.timeout.tree.root);
}


TEST_GROUP_RUNNER(rq_timeout)
{
	RUN_TEST_CASE(rq_timeout, minimum_is_the_earliest_deadline);
	RUN_TEST_CASE(rq_timeout, requests_leave_in_deadline_order);
	RUN_TEST_CASE(rq_timeout, equal_deadlines_are_all_armed);
	RUN_TEST_CASE(rq_timeout, relative_and_absolute_deadlines_share_one_order);
	RUN_TEST_CASE(rq_timeout, cancel_reports_ownership);
	RUN_TEST_CASE(rq_timeout, arming_twice_leaves_the_tree_intact);
}


static void runner(void)
{
	RUN_TEST_GROUP(rq_timeout);
}


int main(int argc, char *argv[])
{
	return (UnityMain(argc, (const char **)argv, runner) == 0) ? 0 : 1;
}
