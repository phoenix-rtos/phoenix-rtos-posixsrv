#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <sys/msg.h>
#include <signal.h>
#include <phoenix/shm.h>

#include <unity_fixture.h>


int check_exists(const char *name, void *_ignore1, void *_ignore2)
{
	static char path[SHM_NAME_MAX];
	int ret;

	ret = snprintf(path, SHM_NAME_MAX, "%s%s", SHM_PATH, name);
	if (ret < 0) {
		printf("Failed to prepare path\n");
		exit(0);
	}

	return lookup(path, _ignore1, _ignore2);
}


#define SHM_NAME "/test_shm_api"
#define SHM_SIZE 4096


TEST_GROUP(shm_api_test);

TEST_SETUP(shm_api_test)
{
	// Clean slate before each test case runs
	shm_unlink(SHM_NAME);
}


TEST_TEAR_DOWN(shm_api_test)
{
	// Guarantee teardown hygiene after every test
	shm_unlink(SHM_NAME);
}


/* Test simple creation and existance lookup */
TEST(shm_api_test, creation_and_existance_lookup)
{
	int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
	TEST_ASSERT_TRUE_MESSAGE(fd >= 0, strerror(errno));

	oid_t dummy_oid;
	int lookup_result = check_exists(SHM_NAME, NULL, &dummy_oid);
	TEST_ASSERT_EQUAL_INT_MESSAGE(0, lookup_result, "The check_exists function should locate the created shm object.");

	close(fd);
}


/* Test if unlink removes namespace entry */
TEST(shm_api_test, unlink_removes_namespace_entry)
{
	int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
	TEST_ASSERT_TRUE_MESSAGE(fd >= 0, strerror(errno));
	close(fd);

	TEST_ASSERT_EQUAL_INT_MESSAGE(0, shm_unlink(SHM_NAME), strerror(errno));

	oid_t dummy_oid;
	int lookup_result = check_exists(SHM_NAME, NULL, &dummy_oid);
	TEST_ASSERT_TRUE_MESSAGE(lookup_result < 0, "File path should no longer be discoverable after unlinking.");
}


/* Test exclusive creation fails on duplicate */
TEST(shm_api_test, exclusive_creation_fail_on_duplicate)
{
	int fd = shm_open(SHM_NAME, O_CREAT | O_EXCL | O_RDWR, 0666);
	TEST_ASSERT_TRUE_MESSAGE(fd >= 0, strerror(errno));

	int fd_dup = shm_open(SHM_NAME, O_CREAT | O_EXCL | O_RDWR, 0666);

	TEST_ASSERT_TRUE_MESSAGE(fd_dup < 0, "Second shm_open with O_EXCL must fail when file exists.");
	TEST_ASSERT_EQUAL_INT_MESSAGE(EEXIST, errno, "Error code must strictly be EEXIST.");

	if (fd_dup >= 0)
		close(fd_dup);
	close(fd);
}


/* Test communication via shared memory buffer */
TEST(shm_api_test, multi_process_independent_open_and_atomic_sync)
{
	int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
	TEST_ASSERT_TRUE_MESSAGE(fd >= 0, strerror(errno));

	typedef struct {
		int ready;
		char message[256];
	} shared_data_t;

	TEST_ASSERT_EQUAL_INT_MESSAGE(0, ftruncate(fd, sizeof(shared_data_t)), strerror(errno));
	close(fd);

	pid_t pid = fork();
	TEST_ASSERT_TRUE_MESSAGE(pid >= 0, "Fork failed.");

	if (pid == 0) {
		/* open shared memory object */
		int child_fd = shm_open(SHM_NAME, O_RDWR, 0666);
		if (child_fd < 0)
			_exit(EXIT_FAILURE);

		/* mmap shared memory object to child memory map */
		shared_data_t *shared = mmap(NULL, sizeof(shared_data_t), PROT_READ | PROT_WRITE, MAP_SHARED, child_fd, 0);
		if (shared == MAP_FAILED) {
			close(child_fd);
			_exit(EXIT_FAILURE);
		}

		/* spin and wait for write from parent process */
		while (__atomic_load_n(&shared->ready, __ATOMIC_ACQUIRE) == 0) {
			usleep(1000);
		}

		int match = (strcmp(shared->message, "Hello from Parent!") == 0);
		munmap(shared, sizeof(shared_data_t));
		close(child_fd);
		_exit(match ? EXIT_SUCCESS : EXIT_FAILURE);
	}
	else {
		/* ensure that that child has already mmaped shared memory */
		usleep(20000);
		int parent_fd = shm_open(SHM_NAME, O_RDWR, 0666);
		TEST_ASSERT_TRUE_MESSAGE(parent_fd >= 0, strerror(errno));

		/* mmap shared memory object to parent memory map */
		shared_data_t *shared = mmap(NULL, sizeof(shared_data_t), PROT_READ | PROT_WRITE, MAP_SHARED, parent_fd, 0);
		TEST_ASSERT_TRUE_MESSAGE(shared != MAP_FAILED, strerror(errno));

		/* signal child from parent process via atomic write */
		snprintf(shared->message, sizeof(shared->message), "Hello from Parent!");
		__atomic_store_n(&shared->ready, 1, __ATOMIC_RELEASE);

		/* wait for child to exit */
		int status;
		waitpid(pid, &status, 0);
		TEST_ASSERT_TRUE_MESSAGE(WIFEXITED(status), "Child process crashed or terminated abnormally.");
		TEST_ASSERT_EQUAL_INT_MESSAGE(EXIT_SUCCESS, WEXITSTATUS(status), "Child process reported assertion failure.");

		munmap(shared, sizeof(shared_data_t));
		close(parent_fd);
	}
}


/* Test if fd remains valid even when unlinked and name not accessible in namespace */
TEST(shm_api_test, unlinked_fd_remains_valid)
{
	int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
	TEST_ASSERT_TRUE_MESSAGE(fd >= 0, strerror(errno));
	TEST_ASSERT_EQUAL_INT(0, ftruncate(fd, SHM_SIZE));

	TEST_ASSERT_EQUAL_INT(0, shm_unlink(SHM_NAME));

	oid_t dummy_oid;
	TEST_ASSERT_TRUE(check_exists(SHM_NAME, NULL, &dummy_oid) < 0);

	char *map_ptr = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	TEST_ASSERT_TRUE_MESSAGE(map_ptr != MAP_FAILED, strerror(errno));

	strcpy(map_ptr, "Data stored in unlinked shm object!");
	TEST_ASSERT_EQUAL_STRING("Data stored in unlinked shm object!", map_ptr);

	munmap(map_ptr, SHM_SIZE);
	close(fd);
}


/* Test unlink from seperate process when file remains open */
TEST(shm_api_test, multiprocess_independent_open_unlink_while_open)
{
	int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
	TEST_ASSERT_TRUE_MESSAGE(fd >= 0, strerror(errno));

	typedef struct {
		int child_attached;
		char payload[256];
	} test6_shared_t;

	TEST_ASSERT_EQUAL_INT(0, ftruncate(fd, sizeof(test6_shared_t)));
	close(fd);

	pid_t pid = fork();
	TEST_ASSERT_TRUE(pid >= 0);

	if (pid == 0) {
		/* open shared memory object */
		int child_fd = shm_open(SHM_NAME, O_RDWR, 0666);
		if (child_fd < 0)
			_exit(EXIT_FAILURE);

		/* mmap shared memory object */
		test6_shared_t *child_shared = mmap(NULL, sizeof(test6_shared_t), PROT_READ | PROT_WRITE, MAP_SHARED, child_fd, 0);
		if (child_shared == MAP_FAILED) {
			close(child_fd);
			_exit(EXIT_FAILURE);
		}

		/* signal to parent that shared memory object is mapped  */
		__atomic_store_n(&child_shared->child_attached, 1, __ATOMIC_RELEASE);
		/* wait for parent to unlink and write */
		usleep(50000);

		/* check if payload is valid even after parent unlinked, unmaped and closed */
		int valid_payload = (strcmp(child_shared->payload, "Initial data written by parent") == 0);
		if (valid_payload) {
			strcpy(child_shared->payload, "Modified by Child on unlinked shm!");
		}

		munmap(child_shared, sizeof(test6_shared_t));
		close(child_fd);
		_exit(valid_payload ? EXIT_SUCCESS : EXIT_FAILURE);
	}
	else {
		/* open shared memory object */
		int parent_fd = shm_open(SHM_NAME, O_RDWR, 0666);
		TEST_ASSERT_TRUE_MESSAGE(parent_fd >= 0, strerror(errno));

		/* mmap shared memory object */
		test6_shared_t *parent_shared = mmap(NULL, sizeof(test6_shared_t), PROT_READ | PROT_WRITE, MAP_SHARED, parent_fd, 0);
		TEST_ASSERT_TRUE_MESSAGE(parent_shared != MAP_FAILED, strerror(errno));

		/* wait and spin until child has mmaped shared memory object */
		while (__atomic_load_n(&parent_shared->child_attached, __ATOMIC_ACQUIRE) == 0) {
			usleep(1000);
		}

		/* unlink, write, unmap, close  */
		TEST_ASSERT_EQUAL_INT(0, shm_unlink(SHM_NAME));
		strcpy(parent_shared->payload, "Initial data written by parent");

		int status;
		waitpid(pid, &status, 0);
		TEST_ASSERT_TRUE(WIFEXITED(status));
		TEST_ASSERT_EQUAL_INT_MESSAGE(EXIT_SUCCESS, WEXITSTATUS(status), "Child process failed validation checks.");

		TEST_ASSERT_EQUAL_STRING("Modified by Child on unlinked shm!", parent_shared->payload);
		munmap(parent_shared, sizeof(test6_shared_t));
		close(parent_fd);
	}
}


/* Test read only memory protection */
TEST(shm_api_test, read_only_protection_mapping)
{
	int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
	TEST_ASSERT_TRUE_MESSAGE(fd >= 0, strerror(errno));
	TEST_ASSERT_EQUAL_INT(0, ftruncate(fd, SHM_SIZE));

	const char *ro_map = mmap(NULL, SHM_SIZE, PROT_READ, MAP_SHARED, fd, 0);
	TEST_ASSERT_TRUE_MESSAGE(ro_map != MAP_FAILED, strerror(errno));

	pid_t pid = fork();
	TEST_ASSERT_TRUE(pid >= 0);

	if (pid == 0) {
		munmap((void *)ro_map, SHM_SIZE);
		close(fd);
		_exit(EXIT_SUCCESS);
	}
	else {
		int status;
		waitpid(pid, &status, 0);
		TEST_ASSERT_TRUE(WIFEXITED(status));
		TEST_ASSERT_EQUAL_INT_MESSAGE(EXIT_SUCCESS, WEXITSTATUS(status), "");

		munmap((void *)ro_map, SHM_SIZE);
		close(fd);
	}
}


static volatile sig_atomic_t g_signal_received = 0;


static void sig_handler(int signo)
{
	g_signal_received = 1;
}


static void wait_for_signal(void)
{
	while (!g_signal_received) {
		pause();
	}
	g_signal_received = 0;
}


/* Test truncation fail when shared memory object remains mapped */
TEST(shm_api_test, truncation_fails_when_mapped_succeeds_after_unlink)
{
	int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
	TEST_ASSERT_TRUE_MESSAGE(fd >= 0, strerror(errno));
	TEST_ASSERT_EQUAL_INT(0, ftruncate(fd, SHM_SIZE));

	void *map_ptr = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	TEST_ASSERT_TRUE_MESSAGE(map_ptr != MAP_FAILED, strerror(errno));

	int ret = ftruncate(fd, SHM_SIZE * 2);
	TEST_ASSERT_TRUE_MESSAGE(ret < 0, "Truncation must fail while SHM object is mapped.");

	TEST_ASSERT_EQUAL_INT(0, munmap(map_ptr, SHM_SIZE));

	ret = ftruncate(fd, SHM_SIZE * 2);
	TEST_ASSERT_EQUAL_INT_MESSAGE(0, ret, "Truncation should succeed after unmapping and unlinking.");

	close(fd);
}


/* Test that seperate process fails truncation when other keep map of shared memory object */
TEST(shm_api_test, multiprocess_truncation_test)
{
	struct sigaction sa;
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGUSR1, &sa, NULL);

	int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
	TEST_ASSERT_TRUE_MESSAGE(fd >= 0, strerror(errno));
	TEST_ASSERT_EQUAL_INT(0, ftruncate(fd, SHM_SIZE));
	close(fd);

	pid_t pid = fork();
	TEST_ASSERT_TRUE_MESSAGE(pid >= 0, "Fork failed.");

	if (pid == 0) {
		int child_fd = shm_open(SHM_NAME, O_RDWR, 0666);
		if (child_fd < 0)
			_exit(EXIT_FAILURE);

		void *map_ptr = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, child_fd, 0);
		if (map_ptr == MAP_FAILED) {
			close(child_fd);
			_exit(EXIT_FAILURE);
		}

		kill(getppid(), SIGUSR1);
		wait_for_signal();

		if (munmap(map_ptr, SHM_SIZE) < 0) {
			close(child_fd);
			_exit(EXIT_FAILURE);
		}

		kill(getppid(), SIGUSR1);
		wait_for_signal();

		int ret = ftruncate(child_fd, SHM_SIZE * 2);
		close(child_fd);

		_exit((ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE);
	}
	else {
		int parent_fd = shm_open(SHM_NAME, O_RDWR, 0666);
		TEST_ASSERT_TRUE_MESSAGE(parent_fd >= 0, strerror(errno));

		wait_for_signal();

		int ret = ftruncate(parent_fd, SHM_SIZE * 2);
		TEST_ASSERT_TRUE_MESSAGE(ret < 0, "Truncation must fail while mapped by another process.");

		kill(pid, SIGUSR1);
		wait_for_signal();
		kill(pid, SIGUSR1);

		int status;
		waitpid(pid, &status, 0);
		TEST_ASSERT_TRUE_MESSAGE(WIFEXITED(status), "Child crashed or terminated abnormally.");
		TEST_ASSERT_EQUAL_INT_MESSAGE(EXIT_SUCCESS, WEXITSTATUS(status), "Child failed truncation after unmapping.");

		close(parent_fd);
		shm_unlink(SHM_NAME);
	}
}


TEST(shm_api_test, multiprocess_lifetime_refcount_race)
{
	shm_unlink(SHM_NAME);

	int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
	TEST_ASSERT_TRUE_MESSAGE(fd >= 0, strerror(errno));
	TEST_ASSERT_EQUAL_INT(0, ftruncate(fd, SHM_SIZE));

	pid_t pid1 = fork();
	TEST_ASSERT_TRUE_MESSAGE(pid1 >= 0, "Fork 1 failed.");

	if (pid1 == 0) {
		int child_fd = shm_open(SHM_NAME, O_RDWR, 0666);
		if (child_fd < 0)
			_exit(EXIT_FAILURE);

		void *map_ptr = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, child_fd, 0);
		if (map_ptr == MAP_FAILED) {
			close(child_fd);
			_exit(EXIT_FAILURE);
		}

		kill(getppid(), SIGUSR1);
		wait_for_signal();

		strcpy((char *)map_ptr, "Hello from Child 1");
		munmap(map_ptr, SHM_SIZE);
		close(child_fd);
		_exit(EXIT_SUCCESS);
	}

	pid_t pid2 = fork();
	TEST_ASSERT_TRUE_MESSAGE(pid2 >= 0, "Fork 2 failed.");

	if (pid2 == 0) {
		wait_for_signal();

		int child_fd = shm_open(SHM_NAME, O_RDWR, 0666);
		int expected_fail = (child_fd < 0 && errno == ENOENT);

		if (child_fd >= 0) {
			close(child_fd);
		}

		_exit(expected_fail ? EXIT_SUCCESS : EXIT_FAILURE);
	}
	wait_for_signal();

	TEST_ASSERT_EQUAL_INT(0, shm_unlink(SHM_NAME));
	kill(pid1, SIGUSR1);

	int status1;
	waitpid(pid1, &status1, 0);
	TEST_ASSERT_TRUE_MESSAGE(WIFEXITED(status1) && WEXITSTATUS(status1) == EXIT_SUCCESS, "Child 1 failed.");

	kill(pid2, SIGUSR1);

	int status2;
	waitpid(pid2, &status2, 0);
	TEST_ASSERT_TRUE_MESSAGE(WIFEXITED(status2) && WEXITSTATUS(status2) == EXIT_SUCCESS, "Child 2 lifetime/lookup check failed.");

	close(fd);
}


TEST_GROUP_RUNNER(shm_api_test)
{
	RUN_TEST_CASE(shm_api_test, creation_and_existance_lookup);
	RUN_TEST_CASE(shm_api_test, unlink_removes_namespace_entry);
	RUN_TEST_CASE(shm_api_test, exclusive_creation_fail_on_duplicate);
	RUN_TEST_CASE(shm_api_test, multi_process_independent_open_and_atomic_sync);
	RUN_TEST_CASE(shm_api_test, unlinked_fd_remains_valid);
	RUN_TEST_CASE(shm_api_test, multiprocess_independent_open_unlink_while_open);
	RUN_TEST_CASE(shm_api_test, read_only_protection_mapping);
	RUN_TEST_CASE(shm_api_test, truncation_fails_when_mapped_succeeds_after_unlink);
	RUN_TEST_CASE(shm_api_test, multiprocess_truncation_test);
	RUN_TEST_CASE(shm_api_test, multiprocess_lifetime_refcount_race);
}


static void runner(void)
{
	RUN_TEST_GROUP(shm_api_test);
}


int main(int argc, const char *argv[])
{
	return (UnityMain(argc, (const char **)argv, runner) == 0) ? 0 : 1;
}
