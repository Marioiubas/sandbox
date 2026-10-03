#!/bin/sh
# broker package post-install (.deb postinst, .rpm %post).
#
# Kernels that gate unprivileged user namespaces behind AppArmor (Ubuntu
# 23.10 and newer) refuse bubblewrap the user namespace it needs for the
# sandbox. The broker-bwrap profile grants `userns` to /usr/bin/bwrap and
# nothing else. Load it only where AppArmor is running and the kernel exposes
# the gate.
#
# This script never changes kernel.apparmor_restrict_unprivileged_userns and
# never touches the system trust store. If the profile does not load, the
# install still succeeds: `broker run` refuses to start an agent without a
# working sandbox (fail closed) and `broker doctor` says what is missing.
set -u

profile=/etc/apparmor.d/broker-bwrap
gate=/proc/sys/kernel/apparmor_restrict_unprivileged_userns

# No AppArmor user-namespace gate on this kernel: nothing to load.
[ -e "$gate" ] || exit 0

# AppArmor is not running (or its parser is missing): nothing to load.
[ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = "Y" ] || exit 0
command -v apparmor_parser >/dev/null 2>&1 || exit 0

if apparmor_parser -r "$profile"; then
    echo "broker: loaded AppArmor profile $profile (user namespaces for /usr/bin/bwrap only)"
else
    echo "broker: could not load AppArmor profile $profile; 'broker run' will refuse to start agents until it loads (see 'broker doctor')" >&2
fi
exit 0
