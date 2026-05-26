.. SPDX-License-Identifier: GPL-2.0
.. Copyright (C) 2022 Casey Schaufler <casey@schaufler-ca.com>
.. Copyright (C) 2022 Intel Corporation

=====================================
Linux Security Modules
=====================================

:Author: Casey Schaufler
:Date: July 2023

Linux security modules (LSM) provide a mechanism to implement
additional access controls to the Linux security policies.

The various security modules may support any of these attributes:

``LSM_ATTR_CURRENT`` is the current, active security context of the
process.
The proc filesystem provides this value in ``/proc/self/attr/current``.
This is supported by the SELinux, Smack and AppArmor security modules.
Smack also provides this value in ``/proc/self/attr/smack/current``.
AppArmor also provides this value in ``/proc/self/attr/apparmor/current``.

``LSM_ATTR_EXEC`` is the security context of the process at the time the
current image was executed.
The proc filesystem provides this value in ``/proc/self/attr/exec``.
This is supported by the SELinux and AppArmor security modules.
AppArmor also provides this value in ``/proc/self/attr/apparmor/exec``.

``LSM_ATTR_FSCREATE`` is the security context of the process used when
creating file system objects.
The proc filesystem provides this value in ``/proc/self/attr/fscreate``.
This is supported by the SELinux security module.

``LSM_ATTR_KEYCREATE`` is the security context of the process used when
creating key objects.
The proc filesystem provides this value in ``/proc/self/attr/keycreate``.
This is supported by the SELinux security module.

``LSM_ATTR_PREV`` is the security context of the process at the time the
current security context was set.
The proc filesystem provides this value in ``/proc/self/attr/prev``.
This is supported by the SELinux and AppArmor security modules.
AppArmor also provides this value in ``/proc/self/attr/apparmor/prev``.

``LSM_ATTR_SOCKCREATE`` is the security context of the process used when
creating socket objects.
The proc filesystem provides this value in ``/proc/self/attr/sockcreate``.
This is supported by the SELinux security module.

Policy configuration
====================

The ``lsm_config_policy()`` system call provides a unified entry point for
loading and modifying LSM policy. It is intended as a portable alternative
to the per-LSM pseudo-filesystems (``securityfs``, ``selinuxfs``,
``smackfs``) so that policy can be configured even when those filesystems
are not mounted -- for example inside an unprivileged container.

The call routes to a per-LSM hook selected by ``lsm_id``. Each LSM
chooses which operations and which capability checks it accepts.

Operation codes
---------------

The ``op`` argument is one of the ``LSM_POLICY_*`` constants defined in
``<linux/lsm.h>``:

``LSM_POLICY_LOAD`` loads a new policy fragment. If a profile with the
same name already exists in the target namespace the call fails with
``-EEXIST``.

``LSM_POLICY_REPLACE`` loads a policy fragment, replacing any existing
profile of the same name in the target namespace.

``LSM_POLICY_REMOVE`` removes a profile (or sub-namespace) by name.

The format of the policy payload is LSM-specific and is described in
the per-LSM administrator documentation under
``Documentation/admin-guide/LSM/``.

LSMs return ``-EOPNOTSUPP`` for any operation they do not implement.

Configuration flags
-------------------

The ``common_flags`` argument controls how the operation is scoped:

``LSM_CONFIG_SELF`` requests that the operation apply to the calling
task's own security domain rather than to the system-wide policy. The
exact meaning -- including whether the operation is permitted without
``CAP_MAC_ADMIN`` -- is LSM-specific. Each LSM that opts in to
``LSM_CONFIG_SELF`` documents its semantics under
``Documentation/admin-guide/LSM/``. LSMs that do not implement the
self-policy hook return ``-EOPNOTSUPP``.

When ``LSM_CONFIG_SELF`` is not set the kernel requires the caller to
hold ``CAP_MAC_ADMIN`` in the initial user namespace; the targeted LSM
then dispatches to its system-policy hook.

Any reserved bit set in ``common_flags`` is rejected with ``-EINVAL``.

The ``flags`` argument is reserved for LSM-specific flags and must
currently be zero; non-zero values are rejected with ``-EOPNOTSUPP``.

Kernel interface
================

Set a security attribute of the current process
-----------------------------------------------

.. kernel-doc:: security/lsm_syscalls.c
    :identifiers: sys_lsm_set_self_attr

Get the specified security attributes of the current process
------------------------------------------------------------

.. kernel-doc:: security/lsm_syscalls.c
    :identifiers: sys_lsm_get_self_attr

.. kernel-doc:: security/lsm_syscalls.c
    :identifiers: sys_lsm_list_modules

Configure a security module's policy
------------------------------------

.. kernel-doc:: security/lsm_syscalls.c
    :identifiers: sys_lsm_config_policy

Additional documentation
========================

* Documentation/security/lsm.rst
* Documentation/security/lsm-development.rst
