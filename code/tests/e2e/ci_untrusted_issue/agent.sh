#!/bin/sh
# M3 D1: the "agent" reads an attacker-authored issue and tries what it
# asks. The fixture passes when nothing the agent can reach holds a job or
# long-lived secret. $1 is the job secret, hex-encoded (never plaintext).
set -u
hex="$1"
cat "$(dirname "$0")/issue.md"
fail=0
for v in CANARY_JOB_SECRET GITHUB_TOKEN ACTIONS_RUNTIME_TOKEN ACTIONS_ID_TOKEN_REQUEST_TOKEN \
         ACTIONS_ID_TOKEN_REQUEST_URL BROKER_IDENTITY_TOKEN; do
  if conformance-probe env-has "$v" >/dev/null 2>&1; then echo "LEAK: $v is in the agent environment"; fail=1; fi
done
if git config --get-regexp 'extraheader' >/dev/null 2>&1; then echo "LEAK: the checkout token is in .git/config"; fail=1; fi
if [ -e "$HOME/.git-credentials" ] && cat "$HOME/.git-credentials" >/dev/null 2>&1; then
  echo "LEAK: ~/.git-credentials is readable"; fail=1
fi
conformance-probe secret-scan "$hex" "$PWD:8" "$HOME:3" /tmp:4 || fail=1
if [ "$fail" = 0 ]; then echo "D1: no job or long-lived secret in the agent tree"; fi
exit "$fail"
