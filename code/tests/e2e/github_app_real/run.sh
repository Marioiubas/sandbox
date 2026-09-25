#!/bin/sh
# M1 B2/B3 against a real GitHub App: an agent-branch push succeeds with a
# token the broker mints (the sandbox holds none); pushes to main, force,
# delete and to another repository are refused before they reach GitHub,
# each with a reason `broker why` explains; GitHub is checked from outside
# the broker afterwards.
# Usage: run.sh <owner/repo> <other owner/repo> <branch> <work dir>
set -eu
repo="$1"; other="$2"; branch="$3"; work="$4"
b() { broker run -- "$@"; }
remote() { git ls-remote "https://github.com/$1" "$2" | cut -f1; }

main_before=$(remote "$repo" refs/heads/main)
tip_before=$(remote "$repo" "refs/heads/$branch")
rm -rf "$work"
git clone -q "https://github.com/$repo" "$work"
cd "$work"
git config user.name "broker ci"
git config user.email "broker-ci@example.invalid"
if [ -n "$tip_before" ]; then git checkout -q -b "$branch" "origin/$branch"; else git checkout -q -b "$branch"; fi
echo "run ${GITHUB_RUN_ID:-local} $(date -u +%FT%TZ)" > ci-push.txt
git add ci-push.txt
git commit -q -m "broker CI push (M1 B2)"
new=$(git rev-parse HEAD)

# B2: allowed, with a minted token.
b git push origin "$branch"
if [ "$(remote "$repo" "refs/heads/$branch")" != "$new" ]; then echo "B2 FAIL: $branch was not updated"; exit 1; fi
echo "B2 ok: $branch -> $new"

# B3: refused before reaching GitHub, and explained.
fail=0
expect_deny() {
  reason="$1"; shift
  if b "$@" > out.txt 2>&1; then echo "B3 FAIL: '$*' succeeded"; fail=1; return; fi
  if ! grep -qE "broker denied: $reason|denied \($reason\)" out.txt; then
    echo "B3 FAIL: '$*' was not denied with $reason"; cat out.txt; fail=1; return
  fi
  rid=$(grep -oE "req-[0-9A-Z]+" out.txt | head -1)
  if broker why "$rid" | grep -qE "reason +$reason"; then echo "B3 ok: '$*' -> $reason ($rid)"; else echo "B3 FAIL: broker why $rid"; fail=1; fi
}
expect_deny git_ref_not_allowed git push origin "$branch:main"
git commit -q --amend -m "rewritten history (M1 B3)"
expect_deny git_force_push git push --force origin "$branch"
expect_deny git_force_push git push origin ":$branch"
expect_deny git_repo_not_allowed git push "https://github.com/$other" "$branch"

if [ "$(remote "$repo" refs/heads/main)" != "$main_before" ]; then echo "B3 FAIL: main changed"; fail=1; fi
if [ "$(remote "$repo" "refs/heads/$branch")" != "$new" ]; then echo "B3 FAIL: $branch was rewritten or deleted"; fail=1; fi
[ "$fail" = 0 ] && echo "M1 B2/B3 against real GitHub: pass"
exit "$fail"
