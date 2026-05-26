// SPDX-License-Identifier: GPL-2.0
/*
 * Linux Security Module infrastructure tests
 * Tests for the lsm_config_policy() system call.
 *
 * Copyright © 2026 Maxime Bélair <maxime.belair@canonical.com>
 */

#define _GNU_SOURCE
#include <linux/lsm.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/capability.h>
#include "../kselftest_harness.h"
#include "common.h"

static int is_lsm_active(__u64 target_id)
{
	const long page_size = sysconf(_SC_PAGESIZE);
	__u64 *ids = calloc(page_size, 1);
	__u32 size = page_size;
	int count;
	int i;

	if (!ids)
		return 0;

	count = lsm_list_modules(ids, &size, 0);
	if (count <= 0) {
		free(ids);
		return 0;
	}

	for (i = 0; i < count; i++) {
		if (ids[i] == target_id) {
			free(ids);
			return 1;
		}
	}

	free(ids);
	return 0;
}

static int has_cap_mac_admin(void)
{
	cap_t cap = cap_get_proc();
	cap_flag_value_t v = CAP_CLEAR;

	if (cap) {
		cap_get_flag(cap, CAP_MAC_ADMIN, CAP_EFFECTIVE, &v);
		cap_free(cap);
	}
	return v == CAP_SET;
}

/*
 * read_file - read the contents of a file into a malloc'd buffer
 * @path: path to the file
 * @out_size: on success, set to the number of bytes read
 *
 * Returns a pointer to the buffer on success, NULL on failure.
 * The caller must free() the returned buffer.
 */
static void *read_file(const char *path, size_t *out_size)
{
	struct stat st;
	void *buf = NULL;
	int fd;
	ssize_t rd;
	size_t total = 0;
	size_t alloc = 0;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return NULL;

	if (fstat(fd, &st) == 0 && st.st_size > 0) {
		buf = malloc(st.st_size);
		if (!buf) {
			close(fd);
			return NULL;
		}
		rd = read(fd, buf, st.st_size);
		close(fd);
		if (rd <= 0) {
			free(buf);
			return NULL;
		}
		*out_size = rd;
		return buf;
	}

	alloc = 64 * 1024;
	buf = malloc(alloc);
	if (!buf) {
		close(fd);
		return NULL;
	}

	while ((rd = read(fd, (char *)buf + total, alloc - total)) > 0) {
		total += rd;
		if (total == alloc) {
			alloc *= 2;
			buf = realloc(buf, alloc);
			if (!buf) {
				close(fd);
				return NULL;
			}
		}
	}
	close(fd);

	if (total == 0) {
		free(buf);
		return NULL;
	}

	*out_size = total;
	return buf;
}

/*
 * Borrow an existing AppArmor profile's compiled raw_data so tests have
 * a valid policy blob to feed lsm_config_policy() with.
 */
static void *borrow_aa_raw_data(size_t *out_size)
{
	const char *dir_path = "/sys/kernel/security/apparmor/policy/profiles";
	DIR *dir = opendir(dir_path);
	struct dirent *ent;
	void *buf = NULL;

	if (!dir)
		return NULL;

	while ((ent = readdir(dir))) {
		char path[512];

		if (ent->d_name[0] == '.')
			continue;
		snprintf(path, sizeof(path), "%s/%s/raw_data",
			 dir_path, ent->d_name);
		buf = read_file(path, out_size);
		if (buf)
			break;
	}
	closedir(dir);
	return buf;
}

/*
 * Run @fn in a forked child after dropping all capabilities. Returns the
 * child's exit status (0 on success).
 */
static int run_unprivileged(int (*fn)(void *), void *arg)
{
	pid_t pid = fork();
	int status;

	if (pid < 0)
		return -1;
	if (pid == 0) {
		cap_t empty = cap_init();

		if (cap_set_proc(empty) < 0) {
			cap_free(empty);
			_exit(2);
		}
		cap_free(empty);
		_exit(fn(arg) & 0xff);
	}
	if (waitpid(pid, &status, 0) != pid)
		return -1;
	if (!WIFEXITED(status))
		return -1;
	return WEXITSTATUS(status);
}

TEST(lsm_id_undef)
{
	const long page_size = sysconf(_SC_PAGESIZE);
	void *buffer = calloc(page_size, 1);

	ASSERT_NE(NULL, buffer);
	errno = 0;
	ASSERT_EQ(-1, lsm_config_policy(LSM_ID_UNDEF, 0, buffer, page_size,
					LSM_CONFIG_SELF, 0));
	ASSERT_EQ(EOPNOTSUPP, errno);

	free(buffer);
}

TEST(op_undef)
{
	const long page_size = sysconf(_SC_PAGESIZE);
	void *buffer = calloc(page_size, 1);

	ASSERT_NE(NULL, buffer);
	errno = 0;
	ASSERT_EQ(-1, lsm_config_policy(LSM_ID_APPARMOR, 0, buffer,
					page_size, LSM_CONFIG_SELF, 0));
	ASSERT_EQ(EOPNOTSUPP, errno);

	free(buffer);
}

TEST(common_flags_invalid)
{
	char buf[16] = {0};

	errno = 0;
	ASSERT_EQ(-1, lsm_config_policy(LSM_ID_APPARMOR, LSM_POLICY_LOAD,
					buf, sizeof(buf), 0xdeadbeef, 0));
	ASSERT_EQ(EINVAL, errno);
}

/*
 * Per-LSM size limits are enforced *after* the common checks. Passing a
 * size larger than AA_PROFILE_MAX_SIZE (32 MiB) must produce E2BIG and
 * must not touch the user buffer, so a dummy pointer is fine.
 */
TEST(oversize_load)
{
	char dummy[16] = {0};
	const __u32 too_big = (1u << 25) + 1;

	if (!has_cap_mac_admin())
		SKIP(return, "This test needs CAP_MAC_ADMIN");
	if (!is_lsm_active(LSM_ID_APPARMOR))
		SKIP(return, "AppArmor is not active");

	errno = 0;
	ASSERT_EQ(-1, lsm_config_policy(LSM_ID_APPARMOR, LSM_POLICY_LOAD,
					dummy, too_big, 0, 0));
	ASSERT_EQ(E2BIG, errno);
}

/* Any non-zero @flags is rejected with EOPNOTSUPP at the LSM hook. */
TEST(flags_nonzero)
{
	char buf[16] = {0};

	if (!is_lsm_active(LSM_ID_APPARMOR))
		SKIP(return, "AppArmor is not active");

	errno = 0;
	ASSERT_EQ(-1, lsm_config_policy(LSM_ID_APPARMOR, LSM_POLICY_LOAD,
					buf, sizeof(buf), LSM_CONFIG_SELF, 1));
	ASSERT_EQ(EOPNOTSUPP, errno);

	if (has_cap_mac_admin()) {
		errno = 0;
		ASSERT_EQ(-1, lsm_config_policy(LSM_ID_APPARMOR,
						LSM_POLICY_LOAD, buf,
						sizeof(buf), 0, 1));
		ASSERT_EQ(EOPNOTSUPP, errno);
	}
}

TEST(zero_size)
{
	void *buffer = calloc(4096, 1);
	__u64 lsm_id = 0;
	int expected;

	if (is_lsm_active(LSM_ID_APPARMOR)) {
		lsm_id = LSM_ID_APPARMOR;
		expected = EINVAL;
	} else if (is_lsm_active(LSM_ID_SELINUX)) {
		lsm_id = LSM_ID_SELINUX;
		expected = EOPNOTSUPP;
	} else if (is_lsm_active(LSM_ID_SMACK)) {
		lsm_id = LSM_ID_SMACK;
		expected = EINVAL;
	} else {
		free(buffer);
		SKIP(return, "No major LSM active");
	}

	ASSERT_NE(NULL, buffer);
	errno = 0;
	ASSERT_EQ(-1, lsm_config_policy(lsm_id, LSM_POLICY_LOAD, buffer, 0,
					LSM_CONFIG_SELF, 0));
	ASSERT_EQ(expected, errno);

	free(buffer);
}

/*
 * Smack system-wide policy load: SMK_LONG_FMT byte + a simple text rule.
 */
TEST(smack_system_load)
{
	static const char rule[] = "\x01selftest_subj selftest_obj rwx\n";
	__u32 size = sizeof(rule) - 1;

	if (!has_cap_mac_admin())
		SKIP(return, "This test needs CAP_MAC_ADMIN");
	if (!is_lsm_active(LSM_ID_SMACK))
		SKIP(return, "Smack is not active");

	errno = 0;
	ASSERT_LE(0, lsm_config_policy(LSM_ID_SMACK, LSM_POLICY_LOAD,
				       (void *)rule, size, 0, 0));
}

/*
 * AppArmor system-wide policy load: borrow an existing compiled profile
 * from securityfs raw_data and load it into a freshly-created AppArmor
 * sub-namespace.
 */
TEST(apparmor_system_load)
{
	const char *subns_name = "lsm_cfg_kselftest";
	const char *subns_dir = "/sys/kernel/security/apparmor/policy/namespaces/lsm_cfg_kselftest";
	size_t name_len = strlen(subns_name);
	size_t raw_size = 0;
	void *raw_data;
	void *buf;

	if (!has_cap_mac_admin())
		SKIP(return, "This test needs CAP_MAC_ADMIN");
	if (!is_lsm_active(LSM_ID_APPARMOR))
		SKIP(return, "AppArmor is not active");

	raw_data = borrow_aa_raw_data(&raw_size);
	if (!raw_data)
		SKIP(return, "No AppArmor raw_data available");

	rmdir(subns_dir);
	if (mkdir(subns_dir, 0755) < 0) {
		free(raw_data);
		SKIP(return, "Cannot create AppArmor sub-namespace");
	}

	buf = malloc(name_len + 1 + raw_size);
	ASSERT_NE(NULL, buf);
	memcpy(buf, subns_name, name_len);
	((char *)buf)[name_len] = '\0';
	memcpy((char *)buf + name_len + 1, raw_data, raw_size);
	free(raw_data);

	errno = 0;
	ASSERT_EQ(0, lsm_config_policy(LSM_ID_APPARMOR, LSM_POLICY_LOAD, buf,
				       name_len + 1 + raw_size, 0, 0));

	free(buf);
	rmdir(subns_dir);
}

/*
 * Helper: build a syscall buffer "<ns>\0<raw_policy>". Caller owns the
 * returned buffer.
 */
static void *build_system_buf(const char *ns_name, const void *raw,
			      size_t raw_size, size_t *out_size)
{
	size_t name_len = strlen(ns_name);
	size_t total = name_len + 1 + raw_size;
	void *buf = malloc(total);

	if (!buf)
		return NULL;
	memcpy(buf, ns_name, name_len);
	((char *)buf)[name_len] = '\0';
	memcpy((char *)buf + name_len + 1, raw, raw_size);
	*out_size = total;
	return buf;
}

/*
 * system_policy LOAD into a nonexistent sub-namespace returns EINVAL
 * (aa_lookupn_ns() fails).
 */
TEST(apparmor_system_bogus_ns)
{
	size_t raw_size = 0;
	void *raw, *buf;
	size_t buf_size;

	if (!has_cap_mac_admin())
		SKIP(return, "This test needs CAP_MAC_ADMIN");
	if (!is_lsm_active(LSM_ID_APPARMOR))
		SKIP(return, "AppArmor is not active");

	raw = borrow_aa_raw_data(&raw_size);
	if (!raw)
		SKIP(return, "No AppArmor raw_data available");

	buf = build_system_buf("no_such_ns_xyz_12345", raw, raw_size,
			       &buf_size);
	ASSERT_NE(NULL, buf);

	errno = 0;
	ASSERT_EQ(-1, lsm_config_policy(LSM_ID_APPARMOR, LSM_POLICY_LOAD,
					buf, buf_size, 0, 0));
	ASSERT_EQ(EINVAL, errno);

	free(buf);
	free(raw);
}

/*
 * ".." is interpreted as a literal namespace name, never as a path
 * escape. It must fail with EINVAL.
 */
TEST(apparmor_system_dotdot_ns)
{
	size_t raw_size = 0;
	void *raw, *buf;
	size_t buf_size;

	if (!has_cap_mac_admin())
		SKIP(return, "This test needs CAP_MAC_ADMIN");
	if (!is_lsm_active(LSM_ID_APPARMOR))
		SKIP(return, "AppArmor is not active");

	raw = borrow_aa_raw_data(&raw_size);
	if (!raw)
		SKIP(return, "No AppArmor raw_data available");

	buf = build_system_buf("..", raw, raw_size, &buf_size);
	ASSERT_NE(NULL, buf);

	errno = 0;
	ASSERT_EQ(-1, lsm_config_policy(LSM_ID_APPARMOR, LSM_POLICY_LOAD,
					buf, buf_size, 0, 0));
	ASSERT_EQ(EINVAL, errno);

	free(buf);
	free(raw);
}

/*
 * A buffer consisting only of a NUL byte (size 1) is rejected with
 * EINVAL: size < 2 is below the minimum the hook accepts.
 */
TEST(apparmor_system_only_nul)
{
	char buf[1] = { '\0' };

	if (!has_cap_mac_admin())
		SKIP(return, "This test needs CAP_MAC_ADMIN");
	if (!is_lsm_active(LSM_ID_APPARMOR))
		SKIP(return, "AppArmor is not active");

	errno = 0;
	ASSERT_EQ(-1, lsm_config_policy(LSM_ID_APPARMOR, LSM_POLICY_LOAD,
					buf, sizeof(buf), 0, 0));
	ASSERT_EQ(EINVAL, errno);
}

/*
 * SELinux system-wide policy load: read the current binary policy from
 * /sys/fs/selinux/policy and reload it (effectively a no-op replace).
 */
TEST(selinux_system_load)
{
	const char *policy_path = "/sys/fs/selinux/policy";
	void *policy = NULL;
	size_t policy_size = 0;

	if (!is_lsm_active(LSM_ID_SELINUX))
		SKIP(return, "SELinux is not active");

	policy = read_file(policy_path, &policy_size);
	if (!policy)
		SKIP(return, "Cannot read SELinux policy");

	errno = 0;
	ASSERT_LE(0, lsm_config_policy(LSM_ID_SELINUX, LSM_POLICY_LOAD,
				       policy, policy_size, 0, 0));

	free(policy);
}

/*
 * AppArmor self_policy LOAD is monotonically restrictive and must NOT
 * require CAP_MAC_ADMIN. An unprivileged caller passing a valid policy
 * must get 0 (loaded into the new transient ns) or EEXIST (when the
 * profile is already present, which can happen if a prior test ran in
 * the same process and the kselftest harness reused the pid -- defensive,
 * normally the kselftest harness forks each test).
 */
static int self_load_child(void *arg)
{
	struct { const void *raw; size_t size; } *a = arg;
	int r;

	errno = 0;
	r = lsm_config_policy(LSM_ID_APPARMOR, LSM_POLICY_LOAD,
			      (void *)a->raw, a->size, LSM_CONFIG_SELF, 0);
	if (r == 0)
		return 0;
	if (r == -1 && errno == EEXIST)
		return 0;
	fprintf(stderr, "%s: r=%d errno=%d\n", __func__, r, errno);
	return 1;
}

TEST(apparmor_self_policy_load_unprivileged)
{
	size_t raw_size = 0;
	void *raw;
	struct { const void *raw; size_t size; } arg;

	if (!is_lsm_active(LSM_ID_APPARMOR))
		SKIP(return, "AppArmor is not active");
	if (!has_cap_mac_admin())
		SKIP(return, "Test setup needs CAP_MAC_ADMIN to fork+drop");

	raw = borrow_aa_raw_data(&raw_size);
	if (!raw)
		SKIP(return, "No AppArmor raw_data available");

	arg.raw = raw;
	arg.size = raw_size;
	ASSERT_EQ(0, run_unprivileged(self_load_child, &arg));
	free(raw);
}

/*
 * Fork inheritance: the transient self_policy_ns must be shared between
 * parent and child via aa_dup_task_ctx(). We verify by having the parent
 * LOAD a blob, then forking; the child should see the same profile in
 * its (inherited) self_policy_ns -- so a second LOAD of the same blob
 * by the child must fail with EEXIST.
 */
TEST(apparmor_self_policy_fork_inherit)
{
	size_t raw_size = 0;
	void *raw;
	int r;
	pid_t pid;
	int status;

	if (!is_lsm_active(LSM_ID_APPARMOR))
		SKIP(return, "AppArmor is not active");
	if (!has_cap_mac_admin())
		SKIP(return, "needs CAP_MAC_ADMIN (LOAD itself is unpriv; "
			     "but we need stable setup)");

	raw = borrow_aa_raw_data(&raw_size);
	if (!raw)
		SKIP(return, "No AppArmor raw_data available");

	/* Parent LOAD. */
	errno = 0;
	r = lsm_config_policy(LSM_ID_APPARMOR, LSM_POLICY_LOAD, raw,
			      raw_size, LSM_CONFIG_SELF, 0);
	ASSERT_TRUE(r == 0 || (r == -1 && errno == EEXIST));

	pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		int rr;

		errno = 0;
		rr = lsm_config_policy(LSM_ID_APPARMOR, LSM_POLICY_LOAD, raw,
				       raw_size, LSM_CONFIG_SELF, 0);
		/* Inherited ns already has this profile -> EEXIST. */
		_exit((rr == -1 && errno == EEXIST) ? 0 : 1);
	}
	ASSERT_EQ(pid, waitpid(pid, &status, 0));
	ASSERT_TRUE(WIFEXITED(status));
	ASSERT_EQ(0, WEXITSTATUS(status));

	free(raw);
}

/*
 * Helper: read /proc/self/attr/current into @buf (NUL-terminated, trailing
 * newline stripped). Returns 0 on success, -1 on failure.
 */
static int read_proc_attr_current(char *buf, size_t buflen)
{
	int fd = open("/proc/self/attr/current", O_RDONLY);
	ssize_t n;
	char *nl;

	if (fd < 0)
		return -1;
	n = read(fd, buf, buflen - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = '\0';
	nl = strchr(buf, '\n');
	if (nl)
		*nl = '\0';
	return 0;
}

/*
 * Confinement: after a self_policy LOAD, the caller's AppArmor label is
 * re-stacked by apparmor_stack_self_policy_profiles(). The exact format
 * of the new label depends on the borrowed profile, so just verify that
 * /proc/self/attr/current changed.
 */
TEST(apparmor_self_policy_confinement_applied)
{
	char before[1024], after[1024];
	size_t raw_size = 0;
	void *raw;
	int r;

	if (!is_lsm_active(LSM_ID_APPARMOR))
		SKIP(return, "AppArmor is not active");
	if (!has_cap_mac_admin())
		SKIP(return, "needs CAP_MAC_ADMIN for stable setup");

	raw = borrow_aa_raw_data(&raw_size);
	if (!raw)
		SKIP(return, "No AppArmor raw_data available");

	ASSERT_EQ(0, read_proc_attr_current(before, sizeof(before)));

	errno = 0;
	r = lsm_config_policy(LSM_ID_APPARMOR, LSM_POLICY_LOAD, raw, raw_size,
			      LSM_CONFIG_SELF, 0);
	if (r == -1 && errno == EEXIST) {
		/*
		 * The borrowed profile is already in the transient ns (the
		 * kselftest harness reused a leftover ns) -- stacking is
		 * only done on the LOAD success path, so we can't observe a
		 * label change here.
		 */
		free(raw);
		SKIP(return, "transient ns already has profile");
	}
	ASSERT_EQ(0, r);

	ASSERT_EQ(0, read_proc_attr_current(after, sizeof(after)));
	ASSERT_STRNE(before, after);

	free(raw);
}

/*
 * Transient namespace reaping: when the last task ctx referencing a
 * self_policy_ns is freed, aa_self_policy_ns_put() must remove the ns
 * from its parent's sub_ns list so it disappears from securityfs.
 *
 * The borrowed profile may stack a label on the child after LOAD which
 * filters the child's view of /sys/.../namespaces (this happens e.g.
 * when running under docker-default). To stay portable we do the
 * enumeration from the parent process (which keeps its original view)
 * while the child blocks on a pipe.
 *
 *   1. parent forks child
 *   2. child LOADs (creates self.<pid>.<rand>), signals parent, waits
 *   3. parent reads signal, enumerates /sys/.../namespaces, finds the
 *      new dir whose name starts with "self.<child_pid>."
 *   4. parent signals child to exit
 *   5. parent waitpid()s, then verifies the ns was reaped
 */
TEST(apparmor_self_policy_ns_reap)
{
	int p2c[2], c2p[2];
	pid_t pid;
	char ns_name[256] = "";
	char prefix[64];
	char ns_path[512];
	struct stat st;
	int retries;
	int status;
	DIR *d;
	struct dirent *e;
	char ch;

	if (!is_lsm_active(LSM_ID_APPARMOR))
		SKIP(return, "AppArmor is not active");
	if (!has_cap_mac_admin())
		SKIP(return, "needs root to read /sys/.../namespaces");

	ASSERT_EQ(0, pipe(p2c));
	ASSERT_EQ(0, pipe(c2p));

	pid = fork();
	ASSERT_GE(pid, 0);
	if (pid == 0) {
		size_t raw_size = 0;
		void *raw;
		int r;

		close(p2c[1]);
		close(c2p[0]);

		raw = borrow_aa_raw_data(&raw_size);
		if (!raw)
			_exit(2);
		errno = 0;
		r = lsm_config_policy(LSM_ID_APPARMOR, LSM_POLICY_LOAD, raw,
				      raw_size, LSM_CONFIG_SELF, 0);
		free(raw);
		if (r != 0 && !(r == -1 && errno == EEXIST))
			_exit(3);

		/* Tell the parent: "LOAD done, my self_policy_ns is alive". */
		if (write(c2p[1], "g", 1) != 1)
			_exit(4);
		/* Block until the parent has finished its enumeration. */
		if (read(p2c[0], &ch, 1) != 1)
			_exit(5);

		_exit(0);
	}
	close(p2c[0]);
	close(c2p[1]);

	/* Wait for the child to finish LOAD. */
	ASSERT_EQ(1, read(c2p[0], &ch, 1));

	/* Enumerate from the parent's view (not affected by any profile the
	 * child may have stacked on itself).
	 */
	d = opendir("/sys/kernel/security/apparmor/policy/namespaces");
	ASSERT_NE(NULL, d);
	snprintf(prefix, sizeof(prefix), "self.%d.", (int)pid);
	while ((e = readdir(d))) {
		if (strncmp(e->d_name, prefix, strlen(prefix)) == 0) {
			snprintf(ns_name, sizeof(ns_name), "%s", e->d_name);
			break;
		}
	}
	closedir(d);
	ASSERT_NE(0, ns_name[0]);

	/* Release the child so it exits and the ns is reaped. */
	ASSERT_EQ(1, write(p2c[1], "g", 1));
	close(p2c[1]);
	close(c2p[0]);

	ASSERT_EQ(pid, waitpid(pid, &status, 0));
	ASSERT_TRUE(WIFEXITED(status));
	ASSERT_EQ(0, WEXITSTATUS(status));

	snprintf(ns_path, sizeof(ns_path),
		 "/sys/kernel/security/apparmor/policy/namespaces/%s",
		 ns_name);

	/*
	 * Task ctx free may lag a few RCU grace periods behind waitpid().
	 * Retry up to ~1 s for the namespace directory to disappear.
	 */
	for (retries = 0; retries < 50; retries++) {
		if (stat(ns_path, &st) == -1 && errno == ENOENT)
			return;
		usleep(20000);
	}

	ASSERT_EQ(-1, stat(ns_path, &st));
	ASSERT_EQ(ENOENT, errno);
}

TEST_HARNESS_MAIN
