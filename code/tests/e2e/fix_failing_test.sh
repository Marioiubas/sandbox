#!/bin/sh
# M0 acceptance A1: `broker run -- <agent>` finishes a "fix failing test" task,
# and (M1) the agent's credential stays outside the sandbox.
#
# usage: tests/e2e/fix_failing_test.sh <claude|codex> [path-to-broker]
#
# Creates a throwaway repository with one failing Python unittest, runs the
# agent headless inside a broker session, then checks ON THE HOST that the
# test passes, that the test file was not modified, and that the audit chain
# verifies. For claude it then checks from inside a claude-code session that
# the credential variable holds only a sentinel and that the keychain item
# and credentials file are unreadable (I1).
# Exit 0 = pass. Needs python3 and the agent CLI on PATH, logged in.
set -eu

agent="${1:?usage: fix_failing_test.sh <claude|codex> [broker]}"
broker="${2:-broker}"
work="$(mktemp -d /tmp/broker-e2e.XXXXXX)"
trap 'rm -rf "$work"' EXIT
repo="$work/repo"
mkdir -p "$repo"
cd "$repo"
git init -q .
cat > calc.py <<'EOF'
def add(a, b):
    return a - b
EOF
cat > test_calc.py <<'EOF'
import unittest
from calc import add


class TestAdd(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)


if __name__ == "__main__":
    unittest.main()
EOF
git add . && git -c user.email=e2e@broker.invalid -c user.name=e2e commit -q -m "failing test"
before="$(shasum test_calc.py | cut -d' ' -f1)"
if python3 -m unittest -q 2>/dev/null; then echo "setup error: test already passes"; exit 2; fi

prompt='The unit test in test_calc.py fails. Fix the bug in calc.py so that `python3 -m unittest` passes. Do not modify test_calc.py. Run the test to confirm.'
case "$agent" in
  claude) set -- claude -p "$prompt" --model "${E2E_CLAUDE_MODEL:-haiku}" --dangerously-skip-permissions ;;
  codex)  set -- codex exec --full-auto "$prompt" ;;
  *) echo "unknown agent $agent"; exit 2 ;;
esac

start=$(date +%s)
"$broker" run -- "$@" || echo "agent exited non-zero ($?)"
echo "agent wall time: $(( $(date +%s) - start ))s"

status=0
if python3 -m unittest -q 2>/dev/null; then echo "PASS: test passes on the host"; else echo "FAIL: test still fails"; status=1; fi
after="$(shasum test_calc.py | cut -d' ' -f1)"
[ "$before" = "$after" ] && echo "PASS: test file unchanged" || { echo "FAIL: test file modified"; status=1; }
[ ! -e .git/hooks/post-commit ] && [ -z "$(git config --get core.fsmonitor || true)" ] && echo "PASS: git config and hooks untouched" || { echo "FAIL: git config or hooks changed"; status=1; }
"$broker" audit verify || status=1

if [ "$agent" = claude ]; then
  inside="$("$broker" run --profile claude-code -- /bin/sh -c '
    case "$CLAUDE_CODE_OAUTH_TOKEN" in brk_s_*) echo sentinel-only;; *) echo NOT-A-SENTINEL;; esac
    /usr/bin/security find-generic-password -s "Claude Code-credentials" >/dev/null 2>&1 && echo KEYCHAIN-READABLE
    cat "$HOME/.claude/.credentials.json" >/dev/null 2>&1 && echo CREDFILE-READABLE
    true' 2>/dev/null)"
  case "$inside" in
    *NOT-A-SENTINEL*|*READABLE*) echo "FAIL: credential reachable in the sandbox: $inside"; status=1 ;;
    *sentinel-only*) echo "PASS: only a sentinel in the sandbox; keychain and credential file unreadable" ;;
    *) echo "FAIL: credential check did not run"; status=1 ;;
  esac
fi
exit $status
