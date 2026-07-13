// SPDX-License-Identifier: GPL-2.0-only
/*
 * AppArmor security module
 *
 * This file contains AppArmor policy manipulation functions
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2017 Canonical Ltd.
 *
 * AppArmor policy namespaces, allow for different sets of policies
 * to be loaded for tasks within the namespace.
 */

#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/ratelimit.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "include/apparmor.h"
#include "include/audit.h"
#include "include/cred.h"
#include "include/policy_ns.h"
#include "include/label.h"
#include "include/policy.h"
#include "include/policy_unpack.h"

/* kernel label */
struct aa_label *kernel_t;

/* root profile namespace */
struct aa_ns *root_ns;
const char *aa_hidden_ns_name = "---";

/**
 * aa_ns_visible - test if @view is visible from @curr
 * @curr: namespace to treat as the parent (NOT NULL)
 * @view: namespace to test if visible from @curr (NOT NULL)
 * @subns: whether view of a subns is allowed
 *
 * Returns: true if @view is visible from @curr else false
 */
bool aa_ns_visible(struct aa_ns *curr, struct aa_ns *view, bool subns)
{
	if (curr == view)
		return true;

	if (!subns)
		return false;

	for ( ; view; view = view->parent) {
		if (view->parent == curr)
			return true;
	}

	return false;
}

/**
 * aa_ns_name - Find the ns name to display for @view from @curr
 * @curr: current namespace (NOT NULL)
 * @view: namespace attempting to view (NOT NULL)
 * @subns: are subns visible
 *
 * Returns: name of @view visible from @curr
 */
const char *aa_ns_name(struct aa_ns *curr, struct aa_ns *view, bool subns)
{
	/* if view == curr then the namespace name isn't displayed */
	if (curr == view)
		return "";

	if (aa_ns_visible(curr, view, subns)) {
		/* at this point if a ns is visible it is in a view ns
		 * thus the curr ns.hname is a prefix of its name.
		 * Only output the virtualized portion of the name
		 * Add + 2 to skip over // separating curr hname prefix
		 * from the visible tail of the views hname
		 */
		return view->base.hname + strlen(curr->base.hname) + 2;
	}

	return aa_hidden_ns_name;
}

static struct aa_profile *alloc_unconfined(const char *name)
{
	struct aa_profile *profile;

	profile = aa_alloc_null(NULL, name, GFP_KERNEL);
	if (!profile)
		return NULL;

	profile->label.flags |= FLAG_IX_ON_NAME_ERROR |
		FLAG_IMMUTIBLE | FLAG_NS_COUNT | FLAG_UNCONFINED;
	profile->mode = APPARMOR_UNCONFINED;

	return profile;
}

/**
 * alloc_ns - allocate, initialize and return a new namespace
 * @prefix: parent namespace name (MAYBE NULL)
 * @name: a preallocated name  (NOT NULL)
 *
 * Returns: refcounted namespace or NULL on failure.
 */
static struct aa_ns *alloc_ns(const char *prefix, const char *name)
{
	struct aa_ns *ns;

	ns = kzalloc_obj(*ns);
	AA_DEBUG(DEBUG_POLICY, "%s(%p)\n", __func__, ns);
	if (!ns)
		return NULL;
	if (!aa_policy_init(&ns->base, prefix, name, GFP_KERNEL))
		goto fail_ns;

	INIT_LIST_HEAD(&ns->sub_ns);
	INIT_LIST_HEAD(&ns->rawdata_list);
	mutex_init(&ns->lock);
	init_waitqueue_head(&ns->wait);
	aa_ns_acct_init(ns);

	/* released by aa_free_ns() */
	ns->unconfined = alloc_unconfined("unconfined");
	if (!ns->unconfined)
		goto fail_unconfined;
	/* ns and ns->unconfined share ns->unconfined refcount */
	ns->unconfined->ns = ns;

	atomic_set(&ns->uniq_null, 0);

	aa_labelset_init(&ns->labels);

	return ns;

fail_unconfined:
	aa_policy_destroy(&ns->base);
fail_ns:
	kfree_sensitive(ns);
	return NULL;
}

/**
 * aa_free_ns - free a profile namespace
 * @ns: the namespace to free  (MAYBE NULL)
 *
 * Requires: All references to the namespace must have been put, if the
 *           namespace was referenced by a profile confining a task,
 */
void aa_free_ns(struct aa_ns *ns)
{
	if (!ns)
		return;

	aa_policy_destroy(&ns->base);
	aa_labelset_destroy(&ns->labels);
	aa_put_ns(ns->parent);

	ns->unconfined->ns = NULL;
	aa_free_profile(ns->unconfined);
	kfree_sensitive(ns);
}

/* Policy-namespace resource accounting and quota admission */

/* min() treating AA_NS_NOLIMIT as +infinity */
static long cap_min(long a, long b)
{
	if (a == AA_NS_NOLIMIT)
		return b;
	if (b == AA_NS_NOLIMIT)
		return a;
	return min(a, b);
}

/* headroom left under @limit given @used */
static long cap_remaining(long limit, long used)
{
	if (limit == AA_NS_NOLIMIT)
		return AA_NS_NOLIMIT;
	return limit > used ? limit - used : 0;
}

/* Decrement a budget-style cap (depth) by one level, floored at 0 */
static long cap_dec(long v)
{
	if (v == AA_NS_NOLIMIT)
		return AA_NS_NOLIMIT;
	return v > 0 ? v - 1 : 0;
}

void aa_ns_acct_init(struct aa_ns *ns)
{
	struct aa_ns_acct *acct = &ns->acct;

	aa_ns_caps_init_unset(&acct->limits);
	aa_ns_caps_init_unset(&acct->child);
	atomic_long_set(&acct->resident, 0);
	atomic_long_set(&acct->profile_count, 0);
	atomic_long_set(&acct->ns_count, 0);
	ratelimit_state_init(&acct->ratelimit,
			     AA_NS_QUOTA_RATELIMIT_INTERVAL,
			     AA_NS_QUOTA_RATELIMIT_BURST);
	/* suppressed records are summarised, not warned about, per ns */
	ratelimit_set_flags(&acct->ratelimit, RATELIMIT_MSG_ON_RELEASE);
}

static void audit_quota_cb(struct audit_buffer *ab, void *va)
{
	struct apparmor_audit_data *ad = aad_of_va(va);

	if (ad->iface.limit)
		audit_log_format(ab, " limit=\"%s\"", ad->iface.limit);
	audit_log_format(ab, " requested=%ld available=%ld",
			 ad->iface.requested, ad->iface.available);
	if (ad->iface.ns) {
		audit_log_format(ab, " namespace=");
		audit_log_untrustedstring(ab, ad->iface.ns);
	}
}

/* audit limit= names for the wire keys, pinned to enum order */
static const char *const aa_policyns_key_names[AA_POLICYNS_KEY_MAX] = {
	[AA_POLICYNS_KEY_MEMORY]	= "memory",
	[AA_POLICYNS_KEY_MAX_PROFILE]	= "max_profile",
	[AA_POLICYNS_KEY_PROFILES]	= "profiles",
	[AA_POLICYNS_KEY_NAMESPACES]	= "namespaces",
	[AA_POLICYNS_KEY_DEPTH]		= "depth",
	[AA_POLICYNS_KEY_CRIU]		= "criu",
	[AA_POLICYNS_KEY_LOAD_RATE]	= "load_rate",
};

static int ns_quota_deny(struct aa_ns *ns, enum aa_policyns_key key,
			 long requested, long available, int error)
{
	DEFINE_AUDIT_DATA(ad, LSM_AUDIT_DATA_NONE, AA_CLASS_NONE, OP_NS_QUOTA);

	if (!__ratelimit(&ns->acct.ratelimit))
		return error;

	ad.subj_label = aa_current_raw_label();
	ad.info = "quota_exceeded";
	ad.error = error;
	ad.iface.ns = ns->base.hname;
	ad.iface.limit = aa_policyns_key_names[key];
	ad.iface.requested = requested;
	ad.iface.available = available;
	aa_audit_msg(AUDIT_APPARMOR_DENIED, &ad, audit_quota_cb);

	return error;
}

/*
 * cap_admit_delta - admit adding @delta of a counted resource under @limit
 *
 * Shared shape of the counted admission checks: quota/no-limit early out,
 * then current usage plus @delta against @limit, denying with @error.
 */
static int cap_admit_delta(struct aa_ns *ns, enum aa_policyns_key key,
			   long limit, atomic_long_t *used, long delta,
			   int error)
{
	long cur;

	if (!aa_g_policy_ns_quota || limit == AA_NS_NOLIMIT)
		return 0;
	cur = atomic_long_read(used);
	if (cur + delta > limit)
		return ns_quota_deny(ns, key, cur + delta,
				     cap_remaining(limit, cur), error);
	return 0;
}

/**
 * aa_ns_admit_create - structural admission for creating a child of @parent
 * @parent: the namespace a child is being created under
 *
 * Requires: @parent->lock held.
 *
 * Returns: 0 to admit, -EDQUOT (count cap) or -ENOSPC (depth cap) to deny.
 */
int aa_ns_admit_create(struct aa_ns *parent)
{
	struct aa_ns_caps *pl = &parent->acct.limits;
	int error;

	if (!aa_g_policy_ns_quota)
		return 0;

	error = cap_admit_delta(parent, AA_POLICYNS_KEY_NAMESPACES,
				pl->namespaces, &parent->acct.ns_count, 1,
				-EDQUOT);
	if (error)
		return error;
	/* a depth cap of N permits N levels below; 0 denies any child */
	if (pl->depth != AA_NS_NOLIMIT && pl->depth <= 0)
		return ns_quota_deny(parent, AA_POLICYNS_KEY_DEPTH, 1, 0,
				     -ENOSPC);

	return 0;
}

/**
 * aa_ns_admit_resident - pre-commit memory accounting check
 * @ns: target namespace (usage counters and audit)
 * @limits: caps to check against, typically the load's tentative caps
 * @delta: net resident bytes the load set adds (new resident minus the
 *	   resident of profiles it replaces); may be negative
 *
 * Requires: @ns->lock held.
 *
 * Returns: 0 to admit, -ENOSPC on breach.
 */
int aa_ns_admit_resident(struct aa_ns *ns, struct aa_ns_caps *limits,
			 long delta)
{
	return cap_admit_delta(ns, AA_POLICYNS_KEY_MEMORY, limits->memory,
			       &ns->acct.resident, delta, -ENOSPC);
}

/**
 * aa_ns_admit_profile_size - per-profile byte cap (max_profile)
 * @ns: target namespace (audit)
 * @limits: caps to check against, typically the load's tentative caps
 * @bytes: the profile's resident size (precomputed by the caller)
 *
 * Returns 0 to admit, -ENOSPC if the profile exceeds max_profile.
 */
int aa_ns_admit_profile_size(struct aa_ns *ns, struct aa_ns_caps *limits,
			     long bytes)
{
	long limit = limits->max_profile;

	if (!aa_g_policy_ns_quota || limit == AA_NS_NOLIMIT)
		return 0;
	if (bytes > limit)
		return ns_quota_deny(ns, AA_POLICYNS_KEY_MAX_PROFILE, bytes,
				     limit, -ENOSPC);
	return 0;
}

/**
 * aa_ns_admit_count - profile-count cap (profiles)
 * @ns: target namespace (usage counters and audit)
 * @limits: caps to check against, typically the load's tentative caps
 * @delta: net non-null profiles the load set adds (may be negative)
 *
 * Requires: @ns->lock held.
 * Returns 0 to admit, -EDQUOT on breach.
 */
int aa_ns_admit_count(struct aa_ns *ns, struct aa_ns_caps *limits, long delta)
{
	if (delta <= 0)
		return 0;
	return cap_admit_delta(ns, AA_POLICYNS_KEY_PROFILES, limits->profiles,
			       &ns->acct.profile_count, delta, -EDQUOT);
}

/**
 * aa_ns_admit_load_set - admit a whole replace set against @ns's caps
 * @ns: target namespace
 * @lh: the load set, a list of struct aa_load_ent
 * @limits: the tentative caps the set is admitted against
 * @udata: the load's raw data (for the retained-rawdata memory term)
 * @fail_ent: out - the profile that broke a per-profile cap, or NULL for a
 *	      whole-set (memory/count) breach; only set when denying
 * @info: out - audit cause string; only set when denying
 *
 * Sum the set's net resident bytes and profile count (new minus the dedup-
 * skipped and replaced old), plus any newly retained rawdata, and check the
 * per-profile, memory and count caps, so a breach rejects the set atomically
 * before anything installs. Null profiles count for memory but not the count.
 *
 * Requires: @ns->lock held.
 *
 * Returns: 0 to admit the set, or a negative errno with *fail_ent and *info set.
 */
int aa_ns_admit_load_set(struct aa_ns *ns, struct list_head *lh,
			 struct aa_ns_caps *limits, struct aa_loaddata *udata,
			 struct aa_load_ent **fail_ent, const char **info)
{
	long new_bytes = 0, old_bytes = 0;
	long new_count = 0, old_count = 0;
	struct aa_load_ent *ent;
	int error;

	if (!aa_g_policy_ns_quota)
		return 0;

	list_for_each_entry(ent, lh, list) {
		long bytes;

		if (ent->old && ent->new->rawdata &&
		    ent->old->rawdata == ent->new->rawdata)
			continue;	/* dedup-skipped at install */

		bytes = ent->new->resident_size;
		if (!(ent->new->label.flags & FLAG_NULL)) {
			error = aa_ns_admit_profile_size(ns, limits, bytes);
			if (error) {
				*fail_ent = ent;
				*info = "profile exceeds max_profile cap";
				return error;
			}
			new_count++;
		}
		new_bytes += bytes;
		if (ent->old) {
			/* credit the exact bytes charged at @old's go-live,
			 * matching the eventual uncharge
			 */
			old_bytes += ent->old->acct_resident;
			if (!(ent->old->label.flags & FLAG_NULL))
				old_count++;
		}
	}
	/* a newly retained rawdata blob is charged too (same condition as
	 * the __aa_fs_create_rawdata call in aa_replace_profiles)
	 */
	if (!udata->dents[AAFS_LOADDATA_DIR] && aa_g_export_binary)
		new_bytes += aa_loaddata_resident_size(udata);

	error = aa_ns_admit_resident(ns, limits, new_bytes - old_bytes);
	if (error) {
		*fail_ent = NULL;	/* whole-set breach, not one profile */
		*info = "namespace memory cap exceeded";
		return error;
	}
	error = aa_ns_admit_count(ns, limits, new_count - old_count);
	if (error) {
		*fail_ent = NULL;
		*info = "namespace profile cap exceeded";
		return error;
	}
	return 0;
}

/**
 * aa_ns_charge_profile - charge a profile's resident policy to its ns
 * @profile: the profile being made live  (NOT NULL)
 *
 * Null profiles are charged for memory but excluded from profile count.
 */
void aa_ns_charge_profile(struct aa_profile *profile)
{
	struct aa_ns *ns = profile->ns;
	long bytes;

	if (!ns || profile->acct_resident)
		return;

	bytes = profile->resident_size;
	profile->acct_resident = bytes;
	atomic_long_add(bytes, &ns->acct.resident);
	if (!(profile->label.flags & FLAG_NULL))
		atomic_long_inc(&ns->acct.profile_count);
}

/**
 * aa_ns_charge_rawdata - charge a retained rawdata blob to @ns
 * @ns: the namespace retaining the blob  (NOT NULL)
 * @data: the blob going onto @ns->rawdata_list  (NOT NULL)
 *
 * Requires: @ns->lock held.
 */
void aa_ns_charge_rawdata(struct aa_ns *ns, struct aa_loaddata *data)
{
	atomic_long_add(aa_loaddata_resident_size(data), &ns->acct.resident);
}

/**
 * aa_ns_uncharge_rawdata - reverse aa_ns_charge_rawdata()
 * @ns: the namespace that retained the blob  (NOT NULL)
 * @data: the blob leaving @ns->rawdata_list  (NOT NULL)
 *
 * Requires: @ns->lock held.
 */
void aa_ns_uncharge_rawdata(struct aa_ns *ns, struct aa_loaddata *data)
{
	atomic_long_sub(aa_loaddata_resident_size(data), &ns->acct.resident);
}

/**
 * aa_ns_uncharge_profile - reverse aa_ns_charge_profile()
 * @profile: the profile being unloaded  (NOT NULL)
 *
 * No-op if the profile was never charged.
 */
void aa_ns_uncharge_profile(struct aa_profile *profile)
{
	struct aa_ns *ns = profile->ns;

	if (!ns || !profile->acct_resident)
		return;

	atomic_long_sub(profile->acct_resident, &ns->acct.resident);
	if (!(profile->label.flags & FLAG_NULL))
		atomic_long_dec(&ns->acct.profile_count);
	profile->acct_resident = 0;
}

/*
 * apply_budget_keys - apply a budget block's keys onto a caps struct
 * @dst: destination caps, treated as a long array in wire-key order
 * @b: parsed budget block
 * @tighten: cap_min() against the existing value (self) vs overwrite (children)
 */
static void apply_budget_keys(struct aa_ns_caps *dst, struct aa_ns_budget *b,
			      bool tighten)
{
	long *cap = (long *)dst;
	int k;

	for (k = 0; k < AA_POLICYNS_KEY_MAX; k++) {
		if (!(b->specified & (1u << k)) || (b->percent & (1u << k)))
			continue;
		cap[k] = tighten ? cap_min(cap[k], b->values[k]) : b->values[k];
	}
}

/**
 * aa_ns_apply_budget - apply one parsed "policyns limits" block to a caps pair
 * @limits: the (tentative) self caps of the namespace the load targets
 * @child: the (tentative) children template of that namespace
 * @b: one parsed budget block
 */
void aa_ns_apply_budget(struct aa_ns_caps *limits, struct aa_ns_caps *child,
			struct aa_ns_budget *b)
{
	switch (b->target) {
	case AA_POLICYNS_TGT_SELF:
		apply_budget_keys(limits, b, true);
		break;
	case AA_POLICYNS_TGT_CHILDREN:
		aa_ns_caps_init_unset(child);
		apply_budget_keys(child, b, false);
		break;
	default:
		break;
	}
}

/* inherit_child_caps - compute a new child's caps from @parent's template */
static void inherit_child_caps(struct aa_ns *child, struct aa_ns *parent)
{
	struct aa_ns_caps *t = &parent->acct.child;
	struct aa_ns_caps *pl = &parent->acct.limits;
	struct aa_ns_caps *cl = &child->acct.limits;
	struct aa_ns_acct *pa = &parent->acct;

	cl->memory = cap_min(t->memory,
			     cap_remaining(pl->memory,
					   atomic_long_read(&pa->resident)));
	cl->profiles = cap_min(t->profiles,
			       cap_remaining(pl->profiles,
					     atomic_long_read(&pa->profile_count)));
	cl->namespaces = cap_min(t->namespaces,
				 cap_remaining(pl->namespaces,
					       atomic_long_read(&pa->ns_count)));
	cl->max_profile = cap_min(t->max_profile, pl->max_profile);
	cl->criu = cap_min(t->criu, pl->criu);
	cl->load_rate = cap_min(t->load_rate, pl->load_rate);
	cl->depth = cap_min(t->depth, cap_dec(pl->depth));
}

/**
 * __aa_lookupn_ns - lookup the namespace matching @hname
 * @view: namespace to search in  (NOT NULL)
 * @hname: hierarchical ns name  (NOT NULL)
 * @n: length of @hname
 *
 * Requires: rcu_read_lock be held
 *
 * Returns: unrefcounted ns pointer or NULL if not found
 *
 * Do a relative name lookup, recursing through profile tree.
 */
struct aa_ns *__aa_lookupn_ns(struct aa_ns *view, const char *hname, size_t n)
{
	struct aa_ns *ns = view;
	const char *split;

	for (split = strnstr(hname, "//", n); split;
	     split = strnstr(hname, "//", n)) {
		ns = __aa_findn_ns(&ns->sub_ns, hname, split - hname);
		if (!ns)
			return NULL;

		n -= split + 2 - hname;
		hname = split + 2;
	}

	if (n)
		return __aa_findn_ns(&ns->sub_ns, hname, n);
	return NULL;
}

/**
 * aa_lookupn_ns  -  look up a policy namespace relative to @view
 * @view: namespace to search in  (NOT NULL)
 * @name: name of namespace to find  (NOT NULL)
 * @n: length of @name
 *
 * Returns: a refcounted namespace on the list, or NULL if no namespace
 *          called @name exists.
 *
 * refcount released by caller
 */
struct aa_ns *aa_lookupn_ns(struct aa_ns *view, const char *name, size_t n)
{
	struct aa_ns *ns = NULL;

	rcu_read_lock();
	ns = aa_get_ns(__aa_lookupn_ns(view, name, n));
	rcu_read_unlock();

	return ns;
}

static struct aa_ns *__aa_create_ns(struct aa_ns *parent, const char *name,
				    struct dentry *dir)
{
	struct aa_ns *ns;
	int error;

	AA_BUG(!parent);
	AA_BUG(!name);
	AA_BUG(!mutex_is_locked(&parent->lock));

	if (parent->level > MAX_NS_DEPTH)
		return ERR_PTR(-ENOSPC);
	/* per-ns structural caps: breadth and depth */
	error = aa_ns_admit_create(parent);
	if (error)
		return ERR_PTR(error);
	ns = alloc_ns(parent->base.hname, name);
	if (!ns)
		return ERR_PTR(-ENOMEM);
	ns->level = parent->level + 1;
	inherit_child_caps(ns, parent);
	mutex_lock_nested(&ns->lock, ns->level);
	error = __aafs_ns_mkdir(ns, ns_subns_dir(parent), name, dir);
	if (error) {
		AA_ERROR("Failed to create interface for ns %s\n",
			 ns->base.name);
		mutex_unlock(&ns->lock);
		aa_free_ns(ns);
		return ERR_PTR(error);
	}
	ns->parent = aa_get_ns(parent);
	list_add_rcu(&ns->base.list, &parent->sub_ns);
	/* account the new direct child against the parent's breadth cap */
	atomic_long_inc(&parent->acct.ns_count);
	/* add list ref */
	aa_get_ns(ns);
	mutex_unlock(&ns->lock);

	return ns;
}

/**
 * __aa_find_or_create_ns - create an ns, fail if it already exists
 * @parent: the parent of the namespace being created
 * @name: the name of the namespace
 * @dir: if not null the dir to put the ns entries in
 *
 * Returns: the a refcounted ns that has been add or an ERR_PTR
 */
struct aa_ns *__aa_find_or_create_ns(struct aa_ns *parent, const char *name,
				     struct dentry *dir)
{
	struct aa_ns *ns;

	AA_BUG(!mutex_is_locked(&parent->lock));

	/* try and find the specified ns */
	/* released by caller */
	ns = aa_get_ns(__aa_find_ns(&parent->sub_ns, name));
	if (!ns)
		ns = __aa_create_ns(parent, name, dir);
	else
		ns = ERR_PTR(-EEXIST);

	/* return ref */
	return ns;
}

/**
 * aa_prepare_ns - find an existing or create a new namespace of @name
 * @parent: ns to treat as parent
 * @name: the namespace to find or add  (NOT NULL)
 *
 * Returns: refcounted namespace or PTR_ERR if failed to create one
 */
struct aa_ns *aa_prepare_ns(struct aa_ns *parent, const char *name)
{
	struct aa_ns *ns;

	mutex_lock_nested(&parent->lock, parent->level);
	/* try and find the specified ns and if it doesn't exist create it */
	/* released by caller */
	ns = aa_get_ns(__aa_find_ns(&parent->sub_ns, name));
	if (!ns)
		ns = __aa_create_ns(parent, name, NULL);
	mutex_unlock(&parent->lock);

	/* return ref */
	return ns;
}

static void __ns_list_release(struct list_head *head);

/**
 * destroy_ns - remove everything contained by @ns
 * @ns: namespace to have it contents removed  (NOT NULL)
 */
static void destroy_ns(struct aa_ns *ns)
{
	if (!ns)
		return;

	mutex_lock_nested(&ns->lock, ns->level);
	/* release all profiles in this namespace */
	__aa_profile_list_release(&ns->base.profiles);

	/* release all sub namespaces */
	__ns_list_release(&ns->sub_ns);

	if (ns->parent) {
		unsigned long flags;

		write_lock_irqsave(&ns->labels.lock, flags);
		__aa_proxy_redirect(ns_unconfined(ns),
				    ns_unconfined(ns->parent));
		write_unlock_irqrestore(&ns->labels.lock, flags);
	}
	__aafs_ns_rmdir(ns);
	mutex_unlock(&ns->lock);
}

/**
 * __aa_remove_ns - remove a namespace and all its children
 * @ns: namespace to be removed  (NOT NULL)
 *
 * Requires: ns->parent->lock be held and ns removed from parent.
 */
void __aa_remove_ns(struct aa_ns *ns)
{
	/* remove ns from namespace list */
	list_del_rcu(&ns->base.list);
	/* release the parent's breadth accounting for this direct child */
	if (ns->parent)
		atomic_long_dec(&ns->parent->acct.ns_count);
	destroy_ns(ns);
	aa_put_ns(ns);
}

/**
 * __ns_list_release - remove all profile namespaces on the list put refs
 * @head: list of profile namespaces  (NOT NULL)
 *
 * Requires: namespace lock be held
 */
static void __ns_list_release(struct list_head *head)
{
	struct aa_ns *ns, *tmp;

	list_for_each_entry_safe(ns, tmp, head, base.list)
		__aa_remove_ns(ns);

}

/**
 * aa_alloc_root_ns - allocate the root profile namespace
 *
 * Returns: %0 on success else error
 *
 */
int __init aa_alloc_root_ns(void)
{
	struct aa_profile *kernel_p;

	/* released by aa_free_root_ns - used as list ref*/
	root_ns = alloc_ns(NULL, "root");
	if (!root_ns)
		return -ENOMEM;

	kernel_p = alloc_unconfined("kernel_t");
	if (!kernel_p) {
		destroy_ns(root_ns);
		aa_free_ns(root_ns);
		return -ENOMEM;
	}
	kernel_t = &kernel_p->label;
	root_ns->unconfined->ns = aa_get_ns(root_ns);

	return 0;
}

 /**
  * aa_free_root_ns - free the root profile namespace
  */
void __init aa_free_root_ns(void)
{
	 struct aa_ns *ns = root_ns;

	 root_ns = NULL;

	 aa_label_free(kernel_t);
	 destroy_ns(ns);
	 aa_put_ns(ns);
}
