// SPDX-License-Identifier: GPL-2.0-only
/*
 * System calls implementing the Linux Security Module API.
 *
 *  Copyright (C) 2022 Casey Schaufler <casey@schaufler-ca.com>
 *  Copyright (C) 2022 Intel Corporation
 */

#include <asm/current.h>
#include <linux/compiler_types.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/security.h>
#include <linux/stddef.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/lsm_hooks.h>
#include <uapi/linux/lsm.h>

#include "lsm.h"

/**
 * lsm_name_to_attr - map an LSM attribute name to its ID
 * @name: name of the attribute
 *
 * Returns the LSM attribute value associated with @name, or 0 if
 * there is no mapping.
 */
u64 lsm_name_to_attr(const char *name)
{
	if (!strcmp(name, "current"))
		return LSM_ATTR_CURRENT;
	if (!strcmp(name, "exec"))
		return LSM_ATTR_EXEC;
	if (!strcmp(name, "fscreate"))
		return LSM_ATTR_FSCREATE;
	if (!strcmp(name, "keycreate"))
		return LSM_ATTR_KEYCREATE;
	if (!strcmp(name, "prev"))
		return LSM_ATTR_PREV;
	if (!strcmp(name, "sockcreate"))
		return LSM_ATTR_SOCKCREATE;
	return LSM_ATTR_UNDEF;
}

/**
 * sys_lsm_set_self_attr - Set current task's security module attribute
 * @attr: which attribute to set
 * @ctx: the LSM contexts
 * @size: size of @ctx
 * @flags: reserved for future use
 *
 * Sets the calling task's LSM context. On success this function
 * returns 0. If the attribute specified cannot be set a negative
 * value indicating the reason for the error is returned.
 */
SYSCALL_DEFINE4(lsm_set_self_attr, unsigned int, attr, struct lsm_ctx __user *,
		ctx, u32, size, u32, flags)
{
	int rc;

	rc = mutex_lock_interruptible(&current->signal->cred_guard_mutex);
	if (rc < 0)
		return rc;
	rc = security_setselfattr(attr, ctx, size, flags);
	mutex_unlock(&current->signal->cred_guard_mutex);
	return rc;
}

/**
 * sys_lsm_get_self_attr - Return current task's security module attributes
 * @attr: which attribute to return
 * @ctx: the user-space destination for the information, or NULL
 * @size: pointer to the size of space available to receive the data
 * @flags: special handling options. LSM_FLAG_SINGLE indicates that only
 * attributes associated with the LSM identified in the passed @ctx be
 * reported.
 *
 * Returns the calling task's LSM contexts. On success this
 * function returns the number of @ctx array elements. This value
 * may be zero if there are no LSM contexts assigned. If @size is
 * insufficient to contain the return data -E2BIG is returned and
 * @size is set to the minimum required size. In all other cases
 * a negative value indicating the error is returned.
 */
SYSCALL_DEFINE4(lsm_get_self_attr, unsigned int, attr, struct lsm_ctx __user *,
		ctx, u32 __user *, size, u32, flags)
{
	return security_getselfattr(attr, ctx, size, flags);
}

/**
 * sys_lsm_list_modules - Return a list of the active security modules
 * @ids: the LSM module ids
 * @size: pointer to size of @ids, updated on return
 * @flags: reserved for future use, must be zero
 *
 * Returns a list of the active LSM ids. On success this function
 * returns the number of @ids array elements. This value may be zero
 * if there are no LSMs active. If @size is insufficient to contain
 * the return data -E2BIG is returned and @size is set to the minimum
 * required size. In all other cases a negative value indicating the
 * error is returned.
 */
SYSCALL_DEFINE3(lsm_list_modules, u64 __user *, ids, u32 __user *, size,
		u32, flags)
{
	u32 total_size = lsm_active_cnt * sizeof(*ids);
	u32 usize;
	int i;

	if (flags)
		return -EINVAL;

	if (get_user(usize, size))
		return -EFAULT;

	if (put_user(total_size, size) != 0)
		return -EFAULT;

	if (usize < total_size)
		return -E2BIG;

	for (i = 0; i < lsm_active_cnt; i++)
		if (put_user(lsm_idlist[i]->id, ids++))
			return -EFAULT;

	return lsm_active_cnt;
}

/**
 * sys_lsm_config_policy - Configure a security module's policy
 * @lsm_id: identifier of the target LSM (one of LSM_ID_*)
 * @op: operation to perform on the policy. Defined operations:
 *
 *	* %LSM_POLICY_LOAD - load a new policy fragment
 *
 *	Operations not supported by the targeted LSM return -EOPNOTSUPP.
 * @buf: user-space pointer to the policy payload. The exact layout is
 *	LSM-specific; refer to the per-LSM admin-guide documentation.
 * @size: size of @buf in bytes
 * @common_flags: handling instructions common to all LSMs. Currently one
 *	flag is defined:
 *
 *	* %LSM_CONFIG_SELF - the configuration applies to the calling
 *	  task's own domain (where the targeted LSM supports it) rather
 *	  than to the system-wide policy. The semantics of "self" vary
 *	  per LSM and are described in the per-LSM admin guide.
 *
 *	Setting any reserved bit in @common_flags returns -EINVAL.
 * @flags: LSM-specific flags. Currently reserved; must be zero. Non-zero
 *	values cause the targeted LSM hook to return -EOPNOTSUPP.
 *
 * Configures the targeted LSM's policy without going through that LSM's
 * pseudo-filesystem, so the call also works in environments where the
 * LSM filesystem is unavailable (e.g. inside a container).
 *
 * Without LSM_CONFIG_SELF the call requires CAP_MAC_ADMIN in the
 * initial user namespace.
 *
 * With LSM_CONFIG_SELF the capability requirement is delegated to the
 * targeted LSM: some LSMs (AppArmor) permit unprivileged self-policy
 * loads because the load is monotonically restrictive and can only
 * further confine the caller; other LSMs (Smack) still require
 * CAP_MAC_ADMIN. See the per-LSM admin guide for details.
 *
 * Return: 0 on success. On failure, returns a negative errno. Common
 * errors:
 *
 *	* %-EOPNOTSUPP - @lsm_id is not registered, the LSM does not
 *	  implement the requested @op, or @flags is non-zero
 *	* %-EINVAL - reserved bits set in @common_flags, or LSM-specific
 *	  payload validation failed
 *	* %-EPERM - CAP_MAC_ADMIN required but not held
 *	* %-E2BIG - @size exceeds the targeted LSM's payload limit
 *	* %-EACCES - the targeted LSM disallowed the operation (e.g.
 *	  AppArmor with apparmor.lock_policy=Y)
 */
SYSCALL_DEFINE6(lsm_config_policy, u32, lsm_id, u32, op, void __user *, buf,
		u32, size, u32, common_flags, u32, flags)
{
	if (common_flags & ~LSM_CONFIG_SELF)
		return -EINVAL;
	if (common_flags & LSM_CONFIG_SELF)
		return security_lsm_config_self_policy(lsm_id, op, buf, size,
						       flags);

	if (!capable(CAP_MAC_ADMIN))
		return -EPERM;

	return security_lsm_config_system_policy(lsm_id, op, buf, size, flags);
}
