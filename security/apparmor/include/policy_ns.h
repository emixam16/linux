/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AppArmor security module
 *
 * This file contains AppArmor policy definitions.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2017 Canonical Ltd.
 */

#ifndef __AA_NAMESPACE_H
#define __AA_NAMESPACE_H

#include <linux/kref.h>
#include <linux/ratelimit.h>

#include "apparmor.h"
#include "apparmorfs.h"
#include "label.h"
#include "policy.h"

struct apparmor_audit_data;

/* Match max depth of user namespaces */
#define MAX_NS_DEPTH 32

/* default per-ns audit ratelimit for OP_NS_QUOTA emission */
#define AA_NS_QUOTA_RATELIMIT_INTERVAL	(5 * HZ)
#define AA_NS_QUOTA_RATELIMIT_BURST	10

/* struct aa_ns_acct - per-namespace resource accounting and caps
 * @limits: caps enforced against this namespace (self)
 * @child: template caps stamped onto namespaces this namespace creates (children)
 * @resident: current resident policy bytes charged to this ns (local scope)
 * @profile_count: current count of non-null profiles in this ns (local)
 * @ns_count: current number of direct child namespaces
 * @ratelimit: bounds OP_NS_QUOTA audit emission
 */
struct aa_ns_acct {
	struct aa_ns_caps limits;
	struct aa_ns_caps child;
	atomic_long_t resident;
	atomic_long_t profile_count;
	atomic_long_t ns_count;
	struct ratelimit_state ratelimit;
};

/* struct aa_ns - namespace for a set of profiles
 * @base: common policy
 * @parent: parent of namespace
 * @lock: lock for modifying the object
 * @acct: accounting for the namespace
 * @unconfined: special unconfined profile for the namespace
 * @sub_ns: list of namespaces under the current namespace.
 * @uniq_null: uniq value used for null learning profiles
 * @uniq_id: a unique id count for the profiles in the namespace
 * @level: level of ns within the tree hierarchy
 * @dents: dentries for the namespaces file entries in apparmorfs
 *
 * An aa_ns defines the set profiles that are searched to determine which
 * profile to attach to a task.  Profiles can not be shared between aa_ns
 * and profile names within a namespace are guaranteed to be unique.  When
 * profiles in separate namespaces have the same name they are NOT considered
 * to be equivalent.
 *
 * Namespaces are hierarchical and only namespaces and profiles below the
 * current namespace are visible.
 *
 * Namespace names must be unique and can not contain the characters :/\0
 */
struct aa_ns {
	struct aa_policy base;
	struct aa_ns *parent;
	struct mutex lock;
	struct aa_ns_acct acct;
	struct aa_profile *unconfined;
	struct list_head sub_ns;
	atomic_t uniq_null;
	long uniq_id;
	int level;
	long revision;
	wait_queue_head_t wait;

	struct aa_labelset labels;
	struct list_head rawdata_list;

	struct dentry *dents[AAFS_NS_SIZEOF];
};

extern struct aa_label *kernel_t;
extern struct aa_ns *root_ns;

extern const char *aa_hidden_ns_name;

#define ns_unconfined(NS) (&(NS)->unconfined->label)

bool aa_ns_visible(struct aa_ns *curr, struct aa_ns *view, bool subns);
const char *aa_ns_name(struct aa_ns *parent, struct aa_ns *child, bool subns);
void aa_free_ns(struct aa_ns *ns);
int aa_alloc_root_ns(void);
void aa_free_root_ns(void);

struct aa_ns *__aa_lookupn_ns(struct aa_ns *view, const char *hname, size_t n);
struct aa_ns *aa_lookupn_ns(struct aa_ns *view, const char *name, size_t n);
struct aa_ns *__aa_find_or_create_ns(struct aa_ns *parent, const char *name,
				     struct dentry *dir, struct aa_label *label);
struct aa_ns *aa_prepare_ns(struct aa_ns *root, const char *name,
			    struct aa_label *label);
void __aa_remove_ns(struct aa_ns *ns);

/* policy-namespace resource accounting (see policy-ns quota feature) */
struct aa_loaddata;
void aa_ns_acct_init(struct aa_ns *ns);
void aa_ns_charge_profile(struct aa_profile *profile);
void aa_ns_uncharge_profile(struct aa_profile *profile);
/* retained rawdata accounting, at the ns->rawdata_list add/remove points */
void aa_ns_charge_rawdata(struct aa_ns *ns, struct aa_loaddata *data);
void aa_ns_uncharge_rawdata(struct aa_ns *ns, struct aa_loaddata *data);
/* structural admission, under parent->lock */
int aa_ns_admit_create(struct aa_ns *parent);
/* memory admission, pre-commit under ns->lock */
int aa_ns_admit_resident(struct aa_ns *ns, struct aa_ns_caps *limits,
			 long delta);
/* per-profile and count admission, under ns->lock */
int aa_ns_admit_profile_size(struct aa_ns *ns, struct aa_ns_caps *limits,
			     long bytes);
int aa_ns_admit_count(struct aa_ns *ns, struct aa_ns_caps *limits, long delta);
/* whole replace-set admission, under ns->lock */
struct aa_load_ent;
int aa_ns_admit_load_set(struct aa_ns *ns, struct list_head *lh,
			 struct aa_ns_caps *limits, struct aa_loaddata *udata,
			 struct aa_load_ent **fail_ent, const char **info);
/* apply one parsed "policyns limits" block to a (tentative) caps pair;
 * returns -EOPNOTSUPP for a construct this kernel does not yet enforce
 */
int aa_ns_apply_budget(struct aa_ns_caps *limits, struct aa_ns_caps *child,
		       struct aa_ns_budget *budget);
/* mediate the policyns permission rule (create/load/replace/remove) */
int aa_policyns_perm(struct aa_label *label, struct aa_ns *target,
		     u32 request, const char *op);
int aa_policyns_create_perm(struct aa_label *label, struct aa_ns *parent,
			    const char *name);

static inline struct aa_profile *aa_deref_parent(struct aa_profile *p)
{
	return rcu_dereference_protected(p->parent,
					 mutex_is_locked(&p->ns->lock));
}

/**
 * aa_get_ns - increment references count on @ns
 * @ns: namespace to increment reference count of (MAYBE NULL)
 *
 * Returns: pointer to @ns, if @ns is NULL returns NULL
 * Requires: @ns must be held with valid refcount when called
 */
static inline struct aa_ns *aa_get_ns(struct aa_ns *ns)
{
	if (ns)
		aa_get_profile(ns->unconfined);

	return ns;
}

/**
 * aa_put_ns - decrement refcount on @ns
 * @ns: namespace to put reference of
 *
 * Decrement reference count of @ns and if no longer in use free it
 */
static inline void aa_put_ns(struct aa_ns *ns)
{
	if (ns)
		aa_put_profile(ns->unconfined);
}

/**
 * __aa_findn_ns - find a namespace on a list by @name
 * @head: list to search for namespace on  (NOT NULL)
 * @name: name of namespace to look for  (NOT NULL)
 * @n: length of @name
 * Returns: unrefcounted namespace
 *
 * Requires: rcu_read_lock be held
 */
static inline struct aa_ns *__aa_findn_ns(struct list_head *head,
					  const char *name, size_t n)
{
	return (struct aa_ns *)__policy_strn_find(head, name, n);
}

static inline struct aa_ns *__aa_find_ns(struct list_head *head,
					 const char *name)
{
	return __aa_findn_ns(head, name, strlen(name));
}

#endif /* AA_NAMESPACE_H */
