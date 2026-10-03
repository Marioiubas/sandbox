#!/bin/sh
# broker package pre-removal (.deb prerm, .rpm %preun).
#
# On removal (not on upgrade) unload the broker-bwrap AppArmor profile, so
# /usr/bin/bwrap loses its user-namespace exception together with the
# package. The profile file is an ordinary package file (not a conffile), so
# the package manager deletes it and it does not come back at the next boot.
# Never changes kernel.apparmor_restrict_unprivileged_userns.
set -u

profile=/etc/apparmor.d/broker-bwrap

case "${1:-}" in
    remove | 0) ;; # dpkg prerm "remove" (also before a purge); rpm erase
    *) exit 0 ;;   # upgrade: the new package's post-install reloads it
esac

[ -f "$profile" ] || exit 0
[ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = "Y" ] || exit 0
command -v apparmor_parser >/dev/null 2>&1 || exit 0

if grep -q '^broker-bwrap ' /sys/kernel/security/apparmor/profiles 2>/dev/null; then
    apparmor_parser -R "$profile" ||
        echo "broker: could not unload AppArmor profile broker-bwrap; it stays loaded until reboot" >&2
fi
exit 0
