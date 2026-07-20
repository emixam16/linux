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
#include <linux/rculist.h>
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

/* @pct percent of @base; unlimited base stays unlimited, floored at 0 */
static long cap_percent(long base, long pct)
{
	if (base == AA_NS_NOLIMIT)
		return AA_NS_NOLIMIT;
	if (pct <= 0)
		return 0;
	/* base and pct are both <= INT_MAX (parse-time), so u64 can't wrap */
	return (long)((u64)base * (u64)pct / 100);
}

/*
 * Serializes subtree cap updates and whole-chain admissions, so admission
 * and charge are atomic against concurrent loads anywhere in the subtree.
 * Ordered strictly before any ns->lock; taken only when subtree caps are in
 * play (aa_ns_subtree_in_play()), never by uncharges - decrementing is
 * always the safe direction.
 */
DEFINE_MUTEX(aa_ns_subtree_lock);

void aa_ns_acct_init(struct aa_ns *ns)
{
	struct aa_ns_acct *acct = &ns->acct;

	aa_ns_capset_init_unset(&acct->caps);
	atomic_long_set(&acct->resident, 0);
	atomic_long_set(&acct->profile_count, 0);
	atomic_long_set(&acct->ns_count, 0);
	atomic_long_set(&acct->subtree_resident, 0);
	atomic_long_set(&acct->subtree_profile_count, 0);
	atomic_long_set(&acct->criu_resident, 0);
	atomic_long_set(&acct->subtree_criu, 0);
	ratelimit_state_init(&acct->ratelimit,
			     AA_NS_QUOTA_RATELIMIT_INTERVAL,
			     AA_NS_QUOTA_RATELIMIT_BURST);
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

	/* a load that does not grow usage can never breach the cap, even on
	 * an already-over-cap ns, so always admit it - else a shrinking or
	 * unchanged load could not recover an over-cap namespace
	 */
	if (delta <= 0)
		return 0;
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
 * Returns: 0 to admit, -EDQUOT to deny (namespaces and depth are count caps).
 */
int aa_ns_admit_create(struct aa_ns *parent)
{
	struct aa_ns_caps *pl = &parent->acct.caps.limits;
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
				     -EDQUOT);

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
 * @ns: the namespace whose cap is checked (audit attribution)
 * @limit: the effective max_profile cap in bytes
 * @bytes: the profile's resident size (precomputed by the caller)
 *
 * Returns 0 to admit, -ENOSPC if the profile exceeds max_profile.
 */
int aa_ns_admit_profile_size(struct aa_ns *ns, long limit, long bytes)
{
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
	return cap_admit_delta(ns, AA_POLICYNS_KEY_PROFILES, limits->profiles,
			       &ns->acct.profile_count, delta, -EDQUOT);
}

/*
 * effective_max_profile - chain-min of the per-profile byte cap
 *
 * A subtree-scoped max_profile bounds every profile loaded below it, so the
 * effective cap is the min over @pend and every ancestor's standing subtree
 * cap; *@owner returns the namespace whose cap binds (audit attribution).
 */
static long effective_max_profile(struct aa_ns *ns, struct aa_ns_capset *pend,
				  struct aa_ns **owner)
{
	long eff = cap_min(pend->limits.max_profile,
			   pend->subtree.max_profile);
	struct aa_ns *a;

	*owner = ns;
	for (a = ns->parent; a; a = a->parent) {
		long m = cap_min(eff, a->acct.caps.subtree.max_profile);

		if (m != eff) {
			eff = m;
			*owner = a;
		}
	}
	return eff;
}

/*
 * admit_subtree_agg - admit a load's net aggregate delta against the chain
 *
 * Checks @ns's tentative subtree caps and every ancestor's standing ones
 * against their aggregates; the caller holds aa_ns_subtree_lock whenever any
 * of these caps is set.
 */
static int admit_subtree_agg(struct aa_ns *ns, struct aa_ns_capset *pend,
			     long bytes, long profiles, long criu)
{
	struct aa_ns *a;
	int error;

	for (a = ns; a; a = a->parent) {
		struct aa_ns_caps *sc = (a == ns) ? &pend->subtree
						  : &a->acct.caps.subtree;

		error = cap_admit_delta(a, AA_POLICYNS_KEY_MEMORY, sc->memory,
					&a->acct.subtree_resident, bytes,
					-ENOSPC);
		if (error)
			return error;
		error = cap_admit_delta(a, AA_POLICYNS_KEY_PROFILES,
					sc->profiles,
					&a->acct.subtree_profile_count,
					profiles, -EDQUOT);
		if (error)
			return error;
		error = cap_admit_delta(a, AA_POLICYNS_KEY_CRIU, sc->criu,
					&a->acct.subtree_criu, criu, -ENOSPC);
		if (error)
			return error;
	}
	return 0;
}

/**
 * aa_ns_subtree_in_play - must a load into @ns serialize on the subtree lock
 * @ns: target namespace of the load
 * @lh: the load set, a list of struct aa_load_ent
 *
 * True if the load carries a subtree-scoped block or the chain up from @ns
 * has a subtree cap set. The lockless chain scan can miss a cap committed
 * concurrently; that load then admits against the caps it saw - the same
 * as a cap lowered below its current usage after the fact.
 */
bool aa_ns_subtree_in_play(struct aa_ns *ns, struct list_head *lh)
{
	struct aa_load_ent *ent;
	struct aa_ns *a;
	int i, k;

	list_for_each_entry(ent, lh, list)
		for (i = 0; i < ent->new->n_budgets; i++)
			if (ent->new->budgets[i].scope ==
			    AA_POLICYNS_SCOPE_SUBTREE)
				return true;

	for (a = ns; a; a = a->parent) {
		const long *cap = (const long *)&a->acct.caps.subtree;

		for (k = 0; k < AA_POLICYNS_KEY_MAX; k++)
			if (READ_ONCE(cap[k]) != AA_NS_NOLIMIT)
				return true;
	}
	return false;
}

/**
 * aa_ns_admit_load_set - admit a whole replace set against @ns's caps
 * @ns: target namespace
 * @lh: the load set, a list of struct aa_load_ent
 * @pend: the tentative capset the set is admitted against
 * @udata: the load's raw data (for the retained-rawdata memory term)
 * @fail_ent: out - the profile that broke a per-profile cap, or NULL for a
 *	      whole-set (memory/count) breach; only set when denying
 * @info: out - audit cause string; only set when denying
 *
 * Sum the set's net resident bytes and profile count (new minus the dedup-
 * skipped and replaced old), plus any newly retained rawdata, and check the
 * per-profile, memory and count caps - local and subtree-scoped up the
 * parent chain - so a breach rejects the whole set before anything
 * installs. Null profiles count for memory but not the count.
 *
 * Requires: @ns->lock held; aa_ns_subtree_lock held when subtree caps are in
 *	     play.
 *
 * Returns: 0 to admit the set, or a negative errno with *fail_ent and *info set.
 */
int aa_ns_admit_load_set(struct aa_ns *ns, struct list_head *lh,
			 struct aa_ns_capset *pend, struct aa_loaddata *udata,
			 struct aa_load_ent **fail_ent, const char **info)
{
	long new_bytes = 0, old_bytes = 0;
	long new_count = 0, old_count = 0;
	long raw_bytes = 0;
	struct aa_load_ent *ent;
	struct aa_ns *mp_owner;
	long mp_limit;
	int error;

	if (!aa_g_policy_ns_quota)
		return 0;

	mp_limit = effective_max_profile(ns, pend, &mp_owner);
	list_for_each_entry(ent, lh, list) {
		long bytes;

		if (ent->old && ent->new->rawdata &&
		    ent->old->rawdata == ent->new->rawdata)
			continue;	/* dedup-skipped at install */

		bytes = ent->new->resident_size;
		if (!(ent->new->label.flags & FLAG_NULL)) {
			error = aa_ns_admit_profile_size(mp_owner, mp_limit,
							 bytes);
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
	 * the __aa_fs_create_rawdata call in aa_replace_profiles); it is
	 * also what the criu reserve caps
	 */
	if (!udata->dents[AAFS_LOADDATA_DIR] && aa_g_export_binary) {
		raw_bytes = aa_loaddata_resident_size(udata);
		new_bytes += raw_bytes;
	}

	error = aa_ns_admit_resident(ns, &pend->limits, new_bytes - old_bytes);
	if (error) {
		*fail_ent = NULL;	/* whole-set breach, not one profile */
		*info = "namespace memory cap exceeded";
		return error;
	}
	error = aa_ns_admit_count(ns, &pend->limits, new_count - old_count);
	if (error) {
		*fail_ent = NULL;
		*info = "namespace profile cap exceeded";
		return error;
	}
	error = cap_admit_delta(ns, AA_POLICYNS_KEY_CRIU, pend->limits.criu,
				&ns->acct.criu_resident, raw_bytes, -ENOSPC);
	if (error) {
		*fail_ent = NULL;
		*info = "namespace criu reserve exceeded";
		return error;
	}
	error = admit_subtree_agg(ns, pend, new_bytes - old_bytes,
				  new_count - old_count, raw_bytes);
	if (error) {
		*fail_ent = NULL;
		*info = "subtree cap exceeded";
		return error;
	}
	return 0;
}

/*
 * acct_rollup - add a usage delta to @ns's and every ancestor's subtree totals
 * @ns: the namespace the delta was charged to  (NOT NULL)
 * @bytes: resident byte delta (may be negative)
 * @profiles: non-null profile count delta (may be negative)
 * @criu: retained raw policy byte delta (may be negative)
 *
 * The parent chain is stable for the life of @ns (each ns holds a ref on its
 * parent and is never reparented), so the lockless atomic walk is safe from
 * any charge/uncharge context.
 */
static void acct_rollup(struct aa_ns *ns, long bytes, long profiles, long criu)
{
	for (; ns; ns = ns->parent) {
		atomic_long_add(bytes, &ns->acct.subtree_resident);
		atomic_long_add(profiles, &ns->acct.subtree_profile_count);
		atomic_long_add(criu, &ns->acct.subtree_criu);
	}
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
	bool counted;
	long bytes;

	if (!ns || profile->acct_resident)
		return;

	bytes = profile->resident_size;
	profile->acct_resident = bytes;
	counted = !(profile->label.flags & FLAG_NULL);
	atomic_long_add(bytes, &ns->acct.resident);
	if (counted)
		atomic_long_inc(&ns->acct.profile_count);
	acct_rollup(ns, bytes, counted ? 1 : 0, 0);
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
	long bytes = aa_loaddata_resident_size(data);

	atomic_long_add(bytes, &ns->acct.resident);
	atomic_long_add(bytes, &ns->acct.criu_resident);
	acct_rollup(ns, bytes, 0, bytes);
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
	long bytes = aa_loaddata_resident_size(data);

	atomic_long_sub(bytes, &ns->acct.resident);
	atomic_long_sub(bytes, &ns->acct.criu_resident);
	acct_rollup(ns, -bytes, 0, -bytes);
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
	bool counted;

	if (!ns || !profile->acct_resident)
		return;

	counted = !(profile->label.flags & FLAG_NULL);
	atomic_long_sub(profile->acct_resident, &ns->acct.resident);
	if (counted)
		atomic_long_dec(&ns->acct.profile_count);
	acct_rollup(ns, -profile->acct_resident, counted ? -1 : 0, 0);
	profile->acct_resident = 0;
}

/*
 * apply_budget_keys - apply a budget block's keys onto a caps struct
 * @dst: destination caps, treated as a long array in wire-key order
 * @b: parsed budget block
 * @tighten: cap_min() against the existing value (self) vs overwrite (children)
 *
 * Percentage values are stored raw; they are resolved against the parent's
 * cap when a child is created, so the ratio has no load-order dependence.
 */
static void apply_budget_keys(struct aa_ns_caps *dst, struct aa_ns_budget *b,
			      bool tighten)
{
	long *cap = (long *)dst;
	int k;

	for (k = 0; k < AA_POLICYNS_KEY_MAX; k++) {
		long v;

		if (!(b->specified & (1u << k)))
			continue;
		v = b->values[k];
		cap[k] = tighten ? cap_min(cap[k], v) : v;
	}
}

/**
 * aa_ns_apply_budget - apply one parsed "policyns limits" block to a capset
 * @caps: the (tentative) capset of the namespace the load targets
 * @b: one parsed budget block
 */
int aa_ns_apply_budget(struct aa_ns_capset *caps, struct aa_ns_budget *b)
{
	bool subtree = b->scope == AA_POLICYNS_SCOPE_SUBTREE;

	/* Some features remains to be implemented and are rejected with -EOPNOTSUPP. */
	if (b->specified & (1u << AA_POLICYNS_KEY_LOAD_RATE))
		return -EOPNOTSUPP;
	/* the parser rejects subtree scope on the other keys at parse time */
	if (subtree && (b->specified & ~AA_POLICYNS_SUBTREE_KEYS))
		return -EINVAL;

	switch (b->target) {
	case AA_POLICYNS_TGT_SELF:
		if (b->percent)		/* % is a per-child ratio only */
			return -EOPNOTSUPP;
		apply_budget_keys(subtree ? &caps->subtree : &caps->limits, b,
				  true);
		return 0;
	case AA_POLICYNS_TGT_CHILDREN:
		/* the block is the template for its scope: last block wins */
		if (subtree) {
			aa_ns_caps_init_unset(&caps->child_subtree);
			apply_budget_keys(&caps->child_subtree, b, false);
			caps->child_subtree_percent = b->percent;
		} else {
			aa_ns_caps_init_unset(&caps->child);
			apply_budget_keys(&caps->child, b, false);
			caps->child_percent = b->percent;
		}
		return 0;
	default:	/* routed targets go through aa_ns_budget_route() */
		return -EINVAL;
	}
}

/* resolve_percent_caps - resolve raw percentage keys against @base's caps */
static void resolve_percent_caps(struct aa_ns_caps *caps, u32 percent,
				 const struct aa_ns_caps *base)
{
	long *cap = (long *)caps;
	const long *b = (const long *)base;
	int k;

	for (k = 0; k < AA_POLICYNS_KEY_MAX; k++)
		if (percent & (1u << k))
			cap[k] = cap_percent(b[k], cap[k]);
}

/*
 * Budget blocks targeting another namespace (descendants, root, :NAME:)
 * apply as a two-phase transaction: everything fallible happens in
 * aa_ns_budget_route() before the load commits, the infallible stamping in
 * aa_ns_budget_stamp_routed() after the load's ns->lock is released, one
 * target lock at a time. A namespace created or removed in between is
 * handled either way: a new one gets the children template, a removed one
 * is stamped while detached (the routed refs keep it alive).
 */

/* one routed budget block resolved to its target namespaces */
struct aa_ns_routed_budget {
	struct list_head list;
	struct aa_ns_budget b;		/* value copy; name not carried over */
	int nr_targets;
	struct aa_ns *targets[] __counted_by(nr_targets);
};

/* next namespace in a depth-first walk below @root, NULL when done */
static struct aa_ns *next_ns_dfs(struct aa_ns *root, struct aa_ns *cur)
{
	struct aa_ns *ns;

	ns = list_first_or_null_rcu(&cur->sub_ns, struct aa_ns, base.list);
	if (ns)
		return ns;
	while (cur != root) {
		ns = list_next_or_null_rcu(&cur->parent->sub_ns,
					   &cur->base.list, struct aa_ns,
					   base.list);
		if (ns)
			return ns;
		cur = cur->parent;
	}
	return NULL;
}

/**
 * aa_ns_budget_route - resolve a routed budget block's targets (fallible)
 * @ns: the namespace the load carrying @b targets
 * @b: a budget block aimed at descendants, root or a named namespace
 * @routed: list the resolved aa_ns_routed_budget is appended to
 * @info: out - audit cause string; only set when failing
 *
 * Requires: @ns->lock held.
 *
 * Returns: 0 with the block queued on @routed, or a negative errno.
 */
static int aa_ns_budget_route(struct aa_ns *ns, struct aa_ns_budget *b,
			      struct list_head *routed, const char **info)
{
	struct aa_ns_routed_budget *r;
	struct aa_ns *target, *cur;
	int n, i;

	/* the parser rejects subtree scope on the other keys at parse time */
	if (b->scope == AA_POLICYNS_SCOPE_SUBTREE &&
	    (b->specified & ~AA_POLICYNS_SUBTREE_KEYS)) {
		*info = "policyns limits: invalid construct";
		return -EINVAL;
	}

	switch (b->target) {
	case AA_POLICYNS_TGT_ROOT:
		/* only a host policy admin may cap the root namespace, and
		 * root has no parent to resolve a percentage against
		 */
		if (b->percent) {
			*info = "policyns limits: invalid construct";
			return -EINVAL;
		}
		if (!aa_current_policy_admin_capable(root_ns)) {
			*info = "policyns limits: not permitted to target the root namespace";
			return -EPERM;
		}
		target = aa_get_ns(root_ns);
		n = 1;
		break;
	case AA_POLICYNS_TGT_NAME:
		target = aa_lookupn_ns(ns, b->name, strlen(b->name));
		if (!target) {
			*info = "policyns limits: target namespace not found";
			return -ENOENT;
		}
		n = 1;
		break;
	case AA_POLICYNS_TGT_DESCENDANTS:
		/* count, then collect refs; the tree may change in between */
		n = 0;
		rcu_read_lock();
		for (cur = next_ns_dfs(ns, ns); cur;
		     cur = next_ns_dfs(ns, cur))
			n++;
		rcu_read_unlock();
		target = NULL;
		break;
	default:
		*info = "policyns limits: invalid construct";
		return -EINVAL;
	}

	r = kzalloc(struct_size(r, targets, n), GFP_KERNEL);
	if (!r) {
		aa_put_ns(target);
		*info = "policyns limits: out of memory";
		return -ENOMEM;
	}
	r->b = *b;
	r->b.name = NULL;	/* owned by the profile, not needed to stamp */
	r->nr_targets = n;
	if (target) {
		r->targets[0] = target;
	} else {
		rcu_read_lock();
		for (cur = next_ns_dfs(ns, ns), i = 0; cur && i < n;
		     cur = next_ns_dfs(ns, cur), i++)
			r->targets[i] = aa_get_ns(cur);
		rcu_read_unlock();
		/* the tree may have shrunk between the passes */
		r->nr_targets = i;
	}
	list_add_tail(&r->list, routed);
	return 0;
}

/* per-key headroom under @p's local caps: the ceiling for a child's cap
 * for key @k (parent remaining for the counted keys, cap_dec for depth,
 * the parent's own cap otherwise). Shared by child inheritance and the
 * :NAME: routed clamp.
 */
static long parent_headroom(struct aa_ns *p, int k)
{
	struct aa_ns_caps *pl = &p->acct.caps.limits;

	switch (k) {
	case AA_POLICYNS_KEY_MEMORY:
		return cap_remaining(pl->memory,
				     atomic_long_read(&p->acct.resident));
	case AA_POLICYNS_KEY_PROFILES:
		return cap_remaining(pl->profiles,
				     atomic_long_read(&p->acct.profile_count));
	case AA_POLICYNS_KEY_NAMESPACES:
		return cap_remaining(pl->namespaces,
				     atomic_long_read(&p->acct.ns_count));
	case AA_POLICYNS_KEY_DEPTH:
		return cap_dec(pl->depth);
	default:	/* max_profile, criu, load_rate: the parent's cap */
		return ((long *)pl)[k];
	}
}

/* stamp one routed block onto @t; requires no other ns lock be held */
static void stamp_routed_budget(struct aa_ns *t, struct aa_ns_budget *b)
{
	bool subtree = b->scope == AA_POLICYNS_SCOPE_SUBTREE;
	struct aa_ns *p = t->parent;
	struct aa_ns_budget rb = *b;
	int k;

	/* parent-then-target, the namespace-creation nesting order; root as
	 * a target has no parent to lock or resolve against
	 */
	if (p)
		mutex_lock_nested(&p->lock, p->level);
	mutex_lock_nested(&t->lock, t->level);
	for (k = 0; k < AA_POLICYNS_KEY_MAX; k++) {
		if (!(rb.specified & (1u << k)))
			continue;
		if (rb.percent & (1u << k))
			rb.values[k] = cap_percent(((const long *)
					(subtree ? &p->acct.caps.subtree
						 : &p->acct.caps.limits))[k],
					rb.values[k]);
		/*
		 * :NAME: overwrites and may raise a local cap, but never past
		 * the parent's remaining headroom - the same limit a new child
		 * gets - so a child is never granted more than the parent holds.
		 * Subtree caps stamp as given: every ancestor's subtree cap
		 * still binds the aggregate at admission.
		 */
		if (b->target == AA_POLICYNS_TGT_NAME && !subtree)
			rb.values[k] = cap_min(rb.values[k],
					       parent_headroom(p, k));
	}
	apply_budget_keys(subtree ? &t->acct.caps.subtree
				  : &t->acct.caps.limits, &rb,
			  b->target != AA_POLICYNS_TGT_NAME);
	mutex_unlock(&t->lock);
	if (p)
		mutex_unlock(&p->lock);
}

/**
 * aa_ns_budget_stamp_routed - apply resolved routed blocks (infallible)
 * @routed: list of aa_ns_routed_budget built by aa_ns_budget_route()
 *
 * Phase two of the routed transaction; called once the load has committed
 * and released its ns->lock. Requires aa_ns_subtree_lock be held when any
 * block carries subtree scope (the load path holds it whenever
 * aa_ns_subtree_in_play() saw such a block).
 */
void aa_ns_budget_stamp_routed(struct list_head *routed)
{
	struct aa_ns_routed_budget *r;
	int i;

	list_for_each_entry(r, routed, list)
		for (i = 0; i < r->nr_targets; i++)
			stamp_routed_budget(r->targets[i], &r->b);
}

/**
 * aa_ns_budget_free_routed - put the target refs and free a routed list
 * @routed: list of aa_ns_routed_budget; empty on return
 */
void aa_ns_budget_free_routed(struct list_head *routed)
{
	struct aa_ns_routed_budget *r, *tmp;
	int i;

	list_for_each_entry_safe(r, tmp, routed, list) {
		for (i = 0; i < r->nr_targets; i++)
			aa_put_ns(r->targets[i]);
		list_del(&r->list);
		kfree(r);
	}
}

/**
 * aa_ns_stage_budget - stage one budget block of a policy load
 * @ns: the namespace the load targets
 * @pend: the load's tentative capset for @ns
 * @b: the parsed budget block
 * @routed: list routed (descendants/root/:NAME:) blocks are queued on
 * @info: out - audit cause string; only set when failing
 *
 * Requires: @ns->lock held.
 */
int aa_ns_stage_budget(struct aa_ns *ns, struct aa_ns_capset *pend,
		       struct aa_ns_budget *b, struct list_head *routed,
		       const char **info)
{
	int error;

	switch (b->target) {
	case AA_POLICYNS_TGT_SELF:
	case AA_POLICYNS_TGT_CHILDREN:
		error = aa_ns_apply_budget(pend, b);
		if (error)
			*info = error == -EINVAL ?
				"policyns limits: invalid construct" :
				"policyns limits: unsupported construct";
		return error;
	default:
		return aa_ns_budget_route(ns, b, routed, info);
	}
}

/* inherit_child_caps - compute a new child's caps from @parent's template */
static void inherit_child_caps(struct aa_ns *child, struct aa_ns *parent)
{
	struct aa_ns_caps *pl = &parent->acct.caps.limits;
	long *cl = (long *)&child->acct.caps.limits;
	struct aa_ns_caps t = parent->acct.caps.child;
	long *tp = (long *)&t;
	struct aa_ns_caps st;
	int k;

	/*
	 * Resolve percentage keys against the parent's cap in a local copy of
	 * the template - never in place - so every child gets the ratio of
	 * the parent's caps as they stand at its creation. Each key is then
	 * clamped to the headroom left under the parent's own cap, the same
	 * ceiling the :NAME: routed clamp uses.
	 */
	resolve_percent_caps(&t, parent->acct.caps.child_percent, pl);
	for (k = 0; k < AA_POLICYNS_KEY_MAX; k++)
		cl[k] = cap_min(tp[k], parent_headroom(parent, k));

	/*
	 * Subtree template: percentages resolve against the parent's own
	 * subtree cap. No headroom clamp - every ancestor's subtree cap
	 * already binds the aggregate at each admission - and the child is
	 * unpublished, so no subtree lock.
	 */
	st = parent->acct.caps.child_subtree;
	resolve_percent_caps(&st, parent->acct.caps.child_subtree_percent,
			     &parent->acct.caps.subtree);
	child->acct.caps.subtree = st;
}

/*
 * Mediation of the "policyns" permission rule (create/load/replace/remove).
 * The class DFA encodes, after the AA_CLASS_POLICY_NS state reached by
 * RULE_MEDIATES(): a \0 separator, a discriminator byte (target enum + 1)
 * and, for the :NAME: target, the namespace name; the verb bits sit on the
 * resulting state. This mirrors the parser's policyns_target_match().
 */

/* which target forms an operation can match, and the :NAME: name to match */
struct policyns_match {
	u16 forms;		/* bitmask of 1 << AA_POLICYNS_TGT_* */
	const char *name;	/* view-relative target name for :NAME:, else NULL */
};

/* true if @ns is a proper descendant of @anc */
static bool policyns_is_descendant(struct aa_ns *anc, struct aa_ns *ns)
{
	for (ns = ns->parent; ns; ns = ns->parent)
		if (ns == anc)
			return true;
	return false;
}

static void policyns_perm_names(struct audit_buffer *ab, u32 mask)
{
	if (mask & AA_POLICYNS_CREATE)
		audit_log_format(ab, "create ");
	if (mask & AA_POLICYNS_LOAD)
		audit_log_format(ab, "load ");
	if (mask & AA_POLICYNS_REPLACE)
		audit_log_format(ab, "replace ");
	if (mask & AA_POLICYNS_REMOVE)
		audit_log_format(ab, "remove ");
}

static void audit_policyns_cb(struct audit_buffer *ab, void *va)
{
	struct apparmor_audit_data *ad = aad_of_va(va);

	if (ad->request & AA_VALID_POLICYNS_PERMS) {
		audit_log_format(ab, " requested=\"");
		policyns_perm_names(ab, ad->request);
		audit_log_format(ab, "\"");
	}
	if (ad->denied & AA_VALID_POLICYNS_PERMS) {
		audit_log_format(ab, " denied=\"");
		policyns_perm_names(ab, ad->denied);
		audit_log_format(ab, "\"");
	}
	if (ad->iface.ns) {
		audit_log_format(ab, " target=");
		audit_log_untrustedstring(ab, ad->iface.ns);
	}
}

/* accumulate the perms the class DFA grants for one target form */
static void policyns_accum(struct aa_policydb *policy, aa_state_t cstate,
			   int target, const char *name, struct aa_perms *accum)
{
	aa_state_t state;

	struct aa_perms *p;

	state = aa_dfa_null_transition(policy->dfa, cstate);
	if (state)
		state = aa_dfa_next(policy->dfa, state, (char)(target + 1));
	if (state && name)
		state = aa_dfa_match(policy->dfa, state, name);
	if (!state)
		return;
	/*
	 * Union the grant across the applicable target forms - a verb is
	 * allowed if any form allows it. The aa_perms_accum() helpers
	 * intersect @allow (they expect @accum preloaded with allperms for
	 * label-component matching), which is the wrong direction here.
	 * aa_check_perms() still gives an explicit deny precedence.
	 */
	p = aa_lookup_perms(policy, state);
	accum->allow |= p->allow;
	accum->deny |= p->deny;
	accum->audit |= p->audit;
	accum->quiet |= p->quiet;
	accum->prompt |= p->prompt;
}

static int policyns_profile_perm(struct aa_profile *profile,
				 struct policyns_match *m,
				 struct apparmor_audit_data *ad, u32 request)
{
	struct aa_ruleset *rules = profile->label.rules[0];
	struct aa_perms perms = { };
	aa_state_t cstate;
	int i;

	ad->subj_label = &profile->label;
	ad->request = request;

	/*
	 * Gate on the class-mediates state, not profile_unconfined(): an
	 * unconfined ns manager that carries a policyns rule still mediates.
	 */
	cstate = RULE_MEDIATES(rules, AA_CLASS_POLICY_NS);
	if (!cstate)
		return 0;

	for (i = AA_POLICYNS_TGT_SELF; i <= AA_POLICYNS_TGT_NAME; i++) {
		if (!(m->forms & (1 << i)))
			continue;
		policyns_accum(rules->policy, cstate, i,
			       i == AA_POLICYNS_TGT_NAME ? m->name : NULL,
			       &perms);
	}
	aa_apply_modes_to_perms(profile, &perms);
	return aa_check_perms(profile, &perms, request, ad, audit_policyns_cb);
}

/**
 * aa_policyns_perm - mediate a policyns operation on an existing @target ns
 * @label: subject label performing the operation  (NOT NULL)
 * @target: the namespace the operation acts on  (NOT NULL)
 * @request: the verb bit (AA_POLICYNS_LOAD/REPLACE/REMOVE)
 * @op: audit operation string
 *
 * Returns: 0 if allowed, else a negative errno.
 */
int aa_policyns_perm(struct aa_label *label, struct aa_ns *target,
		     u32 request, const char *op)
{
	DEFINE_AUDIT_DATA(ad, LSM_AUDIT_DATA_NONE, AA_CLASS_POLICY_NS, op);
	struct aa_ns *subj = labels_ns(label);
	struct policyns_match m = { };
	struct aa_profile *profile;

	if (target == subj)
		m.forms |= 1 << AA_POLICYNS_TGT_SELF;
	if (target == root_ns)
		m.forms |= 1 << AA_POLICYNS_TGT_ROOT;
	if (target->parent == subj)
		m.forms |= 1 << AA_POLICYNS_TGT_CHILDREN;
	if (policyns_is_descendant(subj, target))
		m.forms |= 1 << AA_POLICYNS_TGT_DESCENDANTS;
	/* :NAME: matches the target's name as seen from the subject ns */
	if (target != subj && aa_ns_visible(subj, target, true)) {
		m.name = aa_ns_name(subj, target, true);
		m.forms |= 1 << AA_POLICYNS_TGT_NAME;
	}
	ad.iface.ns = target->base.hname;

	return fn_for_each(label, profile,
			   policyns_profile_perm(profile, &m, &ad, request));
}

/**
 * aa_policyns_create_perm - mediate creating a new ns @name under @parent
 * @label: subject label performing the creation  (NOT NULL)
 * @parent: the namespace the new child is created under  (NOT NULL)
 * @name: the new child's name  (NOT NULL)
 *
 * The parser forbids create against self/root, so only the children,
 * descendants and :NAME: forms can grant it.
 *
 * Returns: 0 if allowed, else a negative errno.
 */
int aa_policyns_create_perm(struct aa_label *label, struct aa_ns *parent,
			    const char *name)
{
	DEFINE_AUDIT_DATA(ad, LSM_AUDIT_DATA_NONE, AA_CLASS_POLICY_NS,
			  OP_POLICYNS);
	struct aa_ns *subj = labels_ns(label);
	struct policyns_match m = { };
	struct aa_profile *profile;
	char namebuf[256];

	/* the new ns is a direct child of @parent */
	if (parent == subj)
		m.forms |= 1 << AA_POLICYNS_TGT_CHILDREN;
	if (parent == subj || policyns_is_descendant(subj, parent))
		m.forms |= 1 << AA_POLICYNS_TGT_DESCENDANTS;
	/* build the new ns name as seen from the subject ns for :NAME: */
	if (parent == subj) {
		m.name = name;
		m.forms |= 1 << AA_POLICYNS_TGT_NAME;
	} else if (aa_ns_visible(subj, parent, true)) {
		int len = snprintf(namebuf, sizeof(namebuf), "%s//%s",
				   aa_ns_name(subj, parent, true), name);

		/*
		 * If the view-relative name does not fit, reject the create:
		 * dropping the :NAME: form while children/descendants still
		 * applied would let a name-targeted deny slip through.
		 */
		if (len < 0 || len >= (int)sizeof(namebuf))
			return -ENAMETOOLONG;
		m.name = namebuf;
		m.forms |= 1 << AA_POLICYNS_TGT_NAME;
	}
	ad.iface.ns = name;

	return fn_for_each(label, profile,
			   policyns_profile_perm(profile, &m,
						 &ad, AA_POLICYNS_CREATE));
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
				    struct dentry *dir, struct aa_label *label)
{
	struct aa_ns *ns;
	int error;

	AA_BUG(!parent);
	AA_BUG(!name);
	AA_BUG(!mutex_is_locked(&parent->lock));

	if (parent->level > MAX_NS_DEPTH)
		return ERR_PTR(-ENOSPC);
	/*
	 * Mediate the policyns create permission at this shared chokepoint,
	 * so mkdir, name-routed loads and every nested level are all gated;
	 * the permission check runs before the quota admission below.
	 */
	error = aa_policyns_create_perm(label, parent, name);
	if (error)
		return ERR_PTR(error);
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
				     struct dentry *dir, struct aa_label *label)
{
	struct aa_ns *ns;

	AA_BUG(!mutex_is_locked(&parent->lock));

	/* try and find the specified ns */
	/* released by caller */
	ns = aa_get_ns(__aa_find_ns(&parent->sub_ns, name));
	if (!ns)
		ns = __aa_create_ns(parent, name, dir, label);
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
struct aa_ns *aa_prepare_ns(struct aa_ns *parent, const char *name,
			    struct aa_label *label)
{
	struct aa_ns *ns;

	mutex_lock_nested(&parent->lock, parent->level);
	/* try and find the specified ns and if it doesn't exist create it */
	/* released by caller */
	ns = aa_get_ns(__aa_find_ns(&parent->sub_ns, name));
	if (!ns)
		ns = __aa_create_ns(parent, name, NULL, label);
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
