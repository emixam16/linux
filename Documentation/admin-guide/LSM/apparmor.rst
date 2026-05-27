========
AppArmor
========

What is AppArmor?
=================

AppArmor is MAC style security extension for the Linux kernel.  It implements
a task centered policy, with task "profiles" being created and loaded
from user space.  Tasks on the system that do not have a profile defined for
them run in an unconfined state which is equivalent to standard Linux DAC
permissions.

How to enable/disable
=====================

set ``CONFIG_SECURITY_APPARMOR=y``

If AppArmor should be selected as the default security module then set::

   CONFIG_DEFAULT_SECURITY_APPARMOR=y

The CONFIG_LSM parameter manages the order and selection of LSMs.
Specify apparmor as the first "major" module (e.g. AppArmor, SELinux, Smack)
in the list.

Build the kernel

If AppArmor is not the default security module it can be enabled by passing
``security=apparmor`` on the kernel's command line.

If AppArmor is the default security module it can be disabled by passing
``apparmor=0, security=XXXX`` (where ``XXXX`` is valid security module), on the
kernel's command line.

For AppArmor to enforce any restrictions beyond standard Linux DAC permissions
policy must be loaded into the kernel from user space (see the Documentation
and tools links).

Loading policy via ``lsm_config_policy()``
==========================================

In addition to the traditional ``apparmorfs`` interfaces under
``/sys/kernel/security/apparmor/``, AppArmor implements the unified
``lsm_config_policy()`` system call described in
``Documentation/userspace-api/lsm.rst``. This is useful in environments
where ``securityfs`` is not mounted, e.g. inside unprivileged containers
that still need to apply their own policy.

System-wide loads
-----------------

A call without ``LSM_CONFIG_SELF`` requires ``CAP_MAC_ADMIN`` in the
initial user namespace, equivalent to writing to the ``.load`` file in
``apparmorfs``.

The payload buffer is laid out as ``"<ns>\0<binary_policy>"``:

* ``<ns>`` is a namespace name relative to the caller's current
  AppArmor namespace. An empty string selects the caller's current
  namespace. The target namespace must already exist (e.g. created by
  ``mkdir`` under ``apparmorfs``); ``..`` is treated as a literal name
  and does not escape.
* ``<binary_policy>`` is the compiled binary policy as produced by
  ``apparmor_parser``.

Self loads
----------

A call with ``LSM_CONFIG_SELF`` loads policy into a transient
sub-namespace owned by the calling task. The namespace is created
lazily on the first such call and is inherited by ``fork()``ed
descendants; it is reaped automatically once the last referring task
exits.

After the load completes, every profile in the transient namespace is
stacked onto the calling task's label via ``aa_label_merge()``, so the
loaded policy actually constrains the caller without an explicit
``change_profile`` call. Because stacking is monotonically restrictive,
the LOAD path does not require ``CAP_MAC_ADMIN``.

The payload buffer for ``LSM_CONFIG_SELF`` is the binary policy alone
(no ``<ns>\0`` prefix).

If the global ``apparmor.lock_policy=Y`` boot parameter is set, all
``lsm_config_policy()`` loads (including self loads) are rejected with
``-EACCES``, matching the existing behavior of the ``.load`` file.

Replacing and removing policy
-----------------------------

Beyond ``LSM_POLICY_LOAD``, AppArmor also implements:

* ``LSM_POLICY_REPLACE``: load a profile, replacing any existing
  profile of the same name in the target namespace. Functionally
  equivalent to writing the policy to the ``.replace`` file in
  ``apparmorfs``. The payload layout matches ``LSM_POLICY_LOAD``.

* ``LSM_POLICY_REMOVE``: remove a profile (or sub-namespace) by
  name. The payload layout is the same ``"<ns>\0<name>"`` for
  system-wide REMOVE; for self REMOVE it is the profile name alone
  (operating on the caller's transient sub-namespace).

Capability rules
~~~~~~~~~~~~~~~~

For system-wide REPLACE and REMOVE the syscall layer requires
``CAP_MAC_ADMIN`` in the initial user namespace, same as LOAD.

For ``LSM_CONFIG_SELF``:

* ``LSM_POLICY_LOAD`` is permitted without ``CAP_MAC_ADMIN`` (it is
  monotonically restrictive).
* ``LSM_POLICY_REPLACE`` and ``LSM_POLICY_REMOVE`` require
  ``CAP_MAC_ADMIN``. REPLACE can swap a restrictive profile for a
  weaker one and REMOVE can unload a stacked profile entirely; either
  could relax confinement that the caller previously imposed on
  itself, so neither is safe to expose unprivileged.

A self REMOVE issued before any prior self-policy LOAD by the calling
task (so no transient sub-namespace has been allocated) returns
``-ENOENT``.

Documentation
=============

Documentation can be found on the wiki, linked below.

Links
=====

Mailing List - apparmor@lists.ubuntu.com

Wiki - http://wiki.apparmor.net

User space tools - https://gitlab.com/apparmor

Kernel module - git://git.kernel.org/pub/scm/linux/kernel/git/jj/linux-apparmor
