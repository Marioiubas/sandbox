# Threat model

`broker` runs a coding agent (Claude Code, Codex, Gemini CLI, Cursor agent)
or any other command inside the operating system's sandbox, and makes the
broker's own egress proxy the only way out. It limits what a hijacked agent
can reach to the task's grants, keeps secrets out of the agent (from
milestone M1), and records every decision outside the sandbox.

It does **not** make an agent trustworthy. Assume the agent's intent can be
hijacked by anything it reads: issues, READMEs, dependencies, web pages, tool
output.

## Non-goals

These are limits of the design, not gaps to be closed later:

1. **Misuse inside granted scope.** An agent holding a legitimate
   `contents:write` grant can still push bad code. A proxy prevents theft,
   not misuse.
2. **Text-only manipulation with no side effect**, such as misrepresenting
   the content of an email to the user.
3. **Host-kernel zero-days in the standard (process-sandbox) tier.** Seatbelt
   and bubblewrap share the host kernel; those threats need the VM hard tier.
4. **Operator abuse** is only partly addressed, through hosted-mode egress
   limits and audit. A broker run by an attacker on the attacker's own
   machine constrains nothing.

Two further residuals follow from the design:

- **Allowed destinations remain exfiltration channels.** A gist or an issue
  on an allowed github.com, a package registry, timing or request counts can
  all carry data. Covert-channel bandwidth is measured and reported, not
  claimed to be zero.
- **The broker is itself custom code** on a hostile boundary. Its parsers are
  property-tested and fuzzed, and the bypass corpus in
  `tests/bypass-corpus/` is public, but its own bugs are in scope as a risk.

## What the broker never claims

It never claims to prevent prompt injection, to make agents safe, to allow
zero exfiltration, or to be escape-proof in the standard tier.

Agent flags such as `--dangerously-skip-permissions`, `--yolo` or
`--full-auto` change only how often the agent asks its user for approval
inside the sandbox. They never change the sandbox, the proxy or the audit.

## What is enforced today (milestone M0)

| Control | macOS (Seatbelt) | Linux (bubblewrap) |
|---|---|---|
| Only route out is the broker | loopback port allowed by the profile, sentinel-authenticated | network namespace with no interface; TCP-to-Unix-socket bridge |
| DNS | no resolver reachable; the broker resolves admitted names only | same |
| Egress policy | allowlist of canonical hosts and ports; IP literals, metadata, private and loopback addresses denied unless granted; DoH endpoints always denied | same |
| TLS | the tunnel must start with a ClientHello whose SNI is the admitted host | same |
| Filesystem | secret stores unreadable; writes only in the repository and session temp; git hooks, git config, the `.git` entry, agent settings, `.mcp.json`, `.envrc` read-only | same, plus Landlock allowlist |
| Kernel attack surface | Apple Events, Launch Services, trustd, DNS service unreachable | seccomp: no new Unix sockets, raw or packet sockets, ptrace, bpf, keyctl, mount, namespaces, io_uring |
| Fail closed | launch refused if any layer, the proxy or the audit log is unavailable; the in-sandbox shim verifies every layer before the agent starts | same |
| Audit | hash-chained SQLite log outside every sandbox; `broker why`, `broker audit verify` | same |

## Known M0 residual risks

- **Credentials are unchanged in M0.** Agents still use their own
  credentials. On macOS the `claude-code` profile may read the login keychain
  so Claude Code can authenticate; this exception ends in M1, when
  credentials move out of the sandbox behind per-session sentinels (ADR-016).
- **macOS per-user temp directory is writable** (`DARWIN_USER_TEMP_DIR`),
  because Apple's toolchain shims reset `TMPDIR` to it (ADR-016). A
  sandboxed agent could tamper with other programs' temporary files there.
- **Tools that ignore proxy variables fail** on macOS: nothing else is
  reachable, which fails closed.
- **Local servers**: the agent cannot open listening sockets that other
  processes connect to, and on Linux with Landlock ABI 4 or newer it can only
  connect to the bridge port, so test suites that start local servers may
  fail inside the sandbox.
- **Processes that leave the agent's process group** are killed on Linux with
  the PID namespace; on macOS they keep running after the session, still
  sandboxed and without any network route.
- **Placeholders** (Linux): protected names missing from the repository get
  empty read-only placeholder directories during a session. They are removed
  at teardown; a crash can leave them behind.

See `docs/policy-reference.md` for the policy file format.
