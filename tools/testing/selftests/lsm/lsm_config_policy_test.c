// SPDX-License-Identifier: GPL-2.0
/*
 * Linux Security Module infrastructure tests
 * Tests for the lsm_config_policy system call
 *
 * Copyright © 2022 Casey Schaufler <casey@schaufler-ca.com>
 */

#define _GNU_SOURCE
#include <linux/lsm.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
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

/*
 * read_file - read the contents of a file into a malloc'd buffer
 * @path: path to the file
 * @out_size: on success, set to the number of bytes read
 *
 * Works with both regular files (uses st_size) and virtual files
 * like sysfs entries that report st_size == 0 (reads in chunks).
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
		/* Regular file with known size */
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

	/* Virtual file (st_size == 0): read in chunks */
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

TEST(lsm_id_undef_lsm_config_policy)
{
	const long page_size = sysconf(_SC_PAGESIZE);
	void *buffer = calloc(page_size, 1);

	ASSERT_NE(NULL, buffer);
	errno = 0;
	ASSERT_EQ(-1, lsm_config_policy(LSM_ID_UNDEF, 0, buffer, page_size, LSM_CONFIG_SELF, 0));
	ASSERT_EQ(EOPNOTSUPP, errno);

	free(buffer);
}

TEST(lsm_op_undef_lsm_config_policy)
{
	const long page_size = sysconf(_SC_PAGESIZE);
	void *buffer = calloc(page_size, 1);

	ASSERT_NE(NULL, buffer);
	errno = 0;
	ASSERT_EQ(-1, lsm_config_policy(LSM_ID_APPARMOR, 0, buffer, page_size, LSM_CONFIG_SELF, 0));
	ASSERT_EQ(EOPNOTSUPP, errno);

	free(buffer);
}

TEST(size_null_lsm_config_policy)
{
	const long page_size = sysconf(_SC_PAGESIZE);
	void *buffer = calloc(page_size, 1);
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
	} else
		SKIP(return, "No major LSM (AppArmor/SELinux/Smack) is active");

	ASSERT_NE(NULL, buffer);
	errno = 0;
	ASSERT_EQ(-1, lsm_config_policy(lsm_id, LSM_POLICY_LOAD, buffer, 0, LSM_CONFIG_SELF, 0));
	ASSERT_EQ(expected , errno);

	free(buffer);
}

/*
 * Smack system-wide policy load: use SMK_LONG_FMT (0x01) with a simple
 * "subject object access" text rule.
 */
TEST(smack_system_load)
{
	/* SMK_LONG_FMT byte + rule text */
	const char rule[] = "\x01" "selftest_subj selftest_obj rwx\n";
	__u32 size = sizeof(rule) - 1; /* exclude the trailing NUL */
        cap_t cap = cap_get_proc();
        cap_flag_value_t is_cap_sys_admin = 0;
        cap_get_flag(cap, CAP_MAC_ADMIN, CAP_EFFECTIVE, &is_cap_sys_admin);
        if (!is_cap_sys_admin)
                SKIP(return, "This test needs CAP_MAC_ADMIN");

	if (!is_lsm_active(LSM_ID_SMACK))
		SKIP(return, "Smack is not active");

	errno = 0;
	ASSERT_LE(0, lsm_config_policy(LSM_ID_SMACK, LSM_POLICY_LOAD, (void *)rule, size, 0, 0));
}

/*
 * AppArmor system-wide policy load: read an existing compiled profile from
 * securityfs raw_data and reload it (effectively a no-op replace).
 *
 * Buffer format: "<ns>\0<binary_policy>"
 * Using an empty namespace name (root ns), so the buffer is "\0" + raw_data.
 */
TEST(apparmor_system_load)
{
	const char *raw_data_dir = "/sys/kernel/security/apparmor/policy/profiles";
	char raw_data_path[512];
	DIR *dir;
	struct dirent *ent;
	void *raw_data = NULL;
	size_t raw_size = 0;
	void *buf;
	int found = 0;
	cap_t cap = cap_get_proc();
	cap_flag_value_t is_cap_sys_admin = 0;
	cap_get_flag(cap, CAP_MAC_ADMIN, CAP_EFFECTIVE, &is_cap_sys_admin);
	if (!is_cap_sys_admin)
		SKIP(return, "This test needs CAP_MAC_ADMIN");

	if (!is_lsm_active(LSM_ID_APPARMOR))
		SKIP(return, "AppArmor is not active");

	dir = opendir(raw_data_dir);
	if (!dir)
		SKIP(return, "Cannot open AppArmor profiles dir");

	/* Find the first profile with a readable raw_data file */
	while ((ent = readdir(dir)) != NULL) {
		if (ent->d_name[0] == '.')
			continue;

		snprintf(raw_data_path, sizeof(raw_data_path),
			 "%s/%s/raw_data", raw_data_dir, ent->d_name);

		raw_data = read_file(raw_data_path, &raw_size);
		if (raw_data) {
			found = 1;
			break;
		}
	}
	closedir(dir);

	if (!found)
		SKIP(return, "No AppArmor raw_data found");

	/*
	 * Build syscall buffer: "\0" (empty ns name) + raw binary policy.
	 */
	buf = malloc(1 + raw_size);
	ASSERT_NE(NULL, buf);
	((char *)buf)[0] = '\0';
	memcpy((char *)buf + 1, raw_data, raw_size);
	free(raw_data);

	errno = 0;
	ASSERT_EQ(0, lsm_config_policy(LSM_ID_APPARMOR, LSM_POLICY_LOAD, buf, 1 + raw_size, 0, 0));

	free(buf);
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

TEST_HARNESS_MAIN
