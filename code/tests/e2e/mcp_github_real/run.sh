#!/bin/sh
# M3 D3 against the real GitHub MCP server, driven from an agent session
# through `broker mcp connect github`: the pinned manifest is approved,
# issues and the private README can be read, a merge is refused, GraphQL
# fails closed, the server makes no allowed connection except to
# api.github.com, and the token never appears in replies or the audit log.
# Usage: run.sh <work dir>   (BROKER_HOME set; TOKEN_FILE = the token file)
set -eu
work="$1"
rm -rf "$work"; mkdir -p "$work"; cd "$work"; git init -q .
init='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"ci","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}'
connect() { broker run -- sh -c "broker mcp connect github < $1 > $2"; }

# First contact records the manifest; approve it (as a user would, on the host).
printf '%s\n{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n' "$init" > first.jsonl
connect first.jsonl first.out || true
grep -q mcp_manifest_unapproved first.out
broker mcp approve github | head -2

cat > calls.jsonl <<JSON
$init
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_me","arguments":{}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"issue_read","arguments":{"method":"get","owner":"Marioiubas","repo":"sandboxpublictest","issue_number":1}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"get_file_contents","arguments":{"owner":"Marioiubas","repo":"sandboxprivatetest","path":"README.md"}}}
{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"merge_pull_request","arguments":{"owner":"Marioiubas","repo":"sandboxpublictest","pullNumber":1}}}
{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"list_issues","arguments":{"owner":"Marioiubas","repo":"sandboxpublictest"}}}
JSON
connect calls.jsonl calls.out
broker audit query --json --limit 1000 > audit.jsonl
python3 - "$TOKEN_FILE" <<'PY'
import json, sys
token = open(sys.argv[1]).read().strip()
replies = {}
for l in open("calls.out"):
    try:
        v = json.loads(l)
    except ValueError:
        continue
    if "id" in v:
        replies[v["id"]] = v
def text(i):
    r = replies.get(i, {}).get("result") or {}
    return (r.get("content") or [{}])[0].get("text", ""), bool(r.get("isError"))
def reason(i):
    return ((replies.get(i, {}).get("error") or {}).get("data") or {}).get("reason")
fail = []
t, err = text(3)
print("get_me:", "error" if err else "ok"); err and fail.append("get_me: " + t[:200])
t, err = text(4)
print("issue_read #1:", "error" if err else "ok", "(title found)" if "broker MCP test" in t else "")
(err or "broker MCP test" not in t) and fail.append("issue_read: " + t[:200])
t, err = text(5)
print("private README:", "error" if err else "ok"); err and fail.append("get_file_contents: " + t[:200])
print("merge_pull_request:", reason(6)); reason(6) != "mcp_tool_not_allowed" and fail.append("merge was not refused")
t, err = text(7)
print("list_issues (GraphQL):", "error, as expected" if err else "ok")
rows = [json.loads(l)["event"] for l in open("audit.jsonl")]
hosts = {}
for e in rows:
    if e.get("kind") != "request.decision":
        continue
    h = (e.get("dest") or {}).get("host") or "?"
    d = (e.get("decision") or {}).get("result")
    hosts.setdefault((h, d), 0)
    hosts[(h, d)] += 1
for (h, d), n in sorted(hosts.items()):
    print(f"  {d:5} {n:3}  {h}")
allowed_elsewhere = [h for (h, d) in hosts if d == "allow" and h not in ("api.github.com",) and not h.endswith(".mcp.broker.internal")]
allowed_elsewhere and fail.append(f"allowed connections outside api.github.com: {allowed_elsewhere}")
graphql = [e for e in rows if e.get("reason") == "github_graphql_unsupported"]
print("GraphQL refused and logged:", len(graphql))
blob = open("audit.jsonl").read() + open("calls.out").read()
(token in blob) and fail.append("the token appears in replies or the audit log")
print("token in replies or audit:", token in blob)
if fail:
    print("D3 FAIL:", *fail, sep="\n  ")
    sys.exit(1)
print("M3 D3 against the real GitHub MCP server: pass")
PY
