#!/bin/sh
# A GitHub API fact ADR-035 relies on: GraphQL does not resolve an issue by
# the number it had before a transfer, while REST redirects to the new
# location (which the broker does not follow; the client's next request is
# decided on its own). Fixture, created 2026-09-26: Marioiubas/sandboxpublictest#2
# was transferred to Marioiubas/sandboxprivatetest#1 (closed). If GitHub
# changes this, confined GraphQL reads could return another repository's
# issue under the old repository's label: this check fails first.
#
# usage: TOKEN_FILE=... sh transfer_check.sh   (the token never reaches argv)
set -eu
auth() { printf 'header = "Authorization: Bearer %s"\n' "$(cat "$TOKEN_FILE")"; }
rest=$(auth | curl -sS -K - -o /dev/null -w '%{http_code} %{redirect_url}' \
  -H 'Accept: application/vnd.github+json' \
  https://api.github.com/repos/Marioiubas/sandboxpublictest/issues/2)
echo "REST sandboxpublictest#2: $rest"
case "$rest" in
  "301 https://api.github.com/repos/Marioiubas/sandboxprivatetest/issues/1") ;;
  *) echo "transfer check: unexpected REST answer (fixture changed?)"; exit 1 ;;
esac
q='{"query":"{ repository(owner: \"Marioiubas\", name: \"sandboxpublictest\") { issue(number: 2) { number } issueOrPullRequest(number: 2) { __typename } } }"}'
gql=$(auth | curl -sS -K - -H 'Content-Type: application/json' --data-binary "$q" https://api.github.com/graphql)
echo "GraphQL sandboxpublictest#2: $gql"
printf '%s' "$gql" | python3 -c '
import json, sys
v = json.load(sys.stdin)
r = (v.get("data") or {}).get("repository") or {}
types = sorted({e.get("type") for e in v.get("errors") or []})
ok = r.get("issue") is None and r.get("issueOrPullRequest") is None and types == ["NOT_FOUND"]
print("GraphQL does not follow the transfer:", ok)
sys.exit(0 if ok else 1)
'
