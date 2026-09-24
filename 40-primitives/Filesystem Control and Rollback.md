---
title: "Filesystem Control and Rollback"
aliases: ["FS Guard", "Copy-on-Write Rollback", "Filesystem Control"]
type: "concept"
section: "primitives"
summary: "Read-only root with writable repo bind, protected subpaths (.git/hooks, .git/config, agent config dirs) re-bound read-only, default deny-read secret dirs, the literal-path deny-glob hole, and copy-on-write rollback (overlayfs upper dir, APFS clone, Docker clone mode)."
tags: [sandbox/primitives, concept, topic/filesystem, topic/isolation, topic/git, platform/linux, platform/macos, control/fs, boundary/tb2, boundary/tb5, invariant/i1, invariant/i5, milestone/m0, evidence/unverified]
status: proposal
confidence: medium
milestone: M0
created: 2026-09-24
updated: 2026-09-24
related: ["[[Sandbox Launcher]]", "[[I5 Config Outside Writable Mounts]]", "[[Landlock]]", "[[bubblewrap]]", "[[Seatbelt]]", "[[Docker Sandboxes]]", "[[Git Smart-HTTP Adapter]]", "[[Cursor DuneSlide Sandbox Escape]]", "[[broker.toml Human Policy Layer]]", "[[Open Questions and Unverified Claims]]", "[[Claude Code Path and Command Injection CVEs]]", "[[Sentinel Swap Pattern]]", "[[Copilot Auto-Approve Settings Write]]", "[[Cursor CurXecute and MCPoison]]", "[[I6 Single Canonicaliser]]", "[[I1 No Secrets in the Sandbox]]", "[[M0 Contained Run]]", "[[Conformance Probe Matrix]]"]
---

# Filesystem Control and Rollback

The sandbox sees a read-only host root, a writable bind of the repository (and tmp), protected subpaths inside the repo re-bound read-only (`.git/hooks`, `.git/config`, agent configuration directories), and secret directories hidden by default. Path rules on Linux are literal, so deny-globs miss files created after start; allowlist-style rules close that hole. Optionally the agent writes into a copy-on-write layer (an overlayfs upper directory on Linux, an APFS clone on macOS, a clone inside a VM) so changes reach the real repo only through a reviewed merge.

## The baseline layout

- **Codex:** `--ro-bind / /`, then `--bind` for writable roots; `.git`, the resolved gitdir and `.codex` re-bound read-only; narrower rules override broader ones (deny `/repo/a` while `/repo` and `/repo/a/b` stay writable) ([Codex linux-sandbox README](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md)).
- **srt:** reads allowed by default with `denyRead`/`allowRead`; writes denied by default with `allowWrite`/`denyWrite`; a mandatory-deny list of shell rc files, `.gitconfig`, `.vscode/`, `.idea/`, `.claude/`; its README warns that write access to PATH directories or shell configs enables code execution in other contexts ([srt](https://github.com/anthropic-experimental/sandbox-runtime)).
- **Claude Code `mask`** can mask secrets inside files such as `~/.config/gh/hosts.yml` via an `extract` regex on Linux/WSL2, while macOS blocks the file instead ([Claude Code docs](https://code.claude.com/docs/en/sandboxing)); see [[Sentinel Swap Pattern]].

**Proposal** (research note 05 §3.2 FS guard; report `broker.toml` example). Default lists, compiled from Cedar `fs.*` grants into SBPL, bwrap binds and Landlock rulesets:

| List | Paths |
|---|---|
| writable | `${repo}`, `${tmp}` |
| deny-read | `~/.ssh`, `~/.aws`, `~/.config/gh`, `~/.netrc`, `~/.docker/config.json`, browser profiles, the keychain DB |
| deny-write (even inside writable roots) | shell rc files, `.git/hooks`, `.git/config`, agent settings dirs (`.claude/`, `.codex/`, `.cursor/`, `.vscode/`, `.idea/`), MCP config files |
| never mounted | `$HOME` as a whole, `docker.sock`, the broker binary's directory, `ctl.sock` |

The human layer is `filesystem.write` and `filesystem.deny_read` in [[broker.toml Human Policy Layer]].

## Protect `.git/hooks` and `.git/config`, not all of `.git`

**Proposal** (report). Hooks, `core.fsmonitor`, `core.sshCommand` and filter drivers in `.git/config` become code execution in the user's next *unsandboxed* git command. The agent still needs to commit locally, so `.git/objects`, `.git/refs` and the index stay writable; the broker performs the push through [[Git Smart-HTTP Adapter]] with a token scoped to the repo and branch. Codex protects all of `.git` ([Codex linux-sandbox README](https://raw.githubusercontent.com/openai/codex/main/codex-rs/linux-sandbox/README.md)); the broker's narrower rule keeps local commits working.

This is the filesystem half of [[I5 Config Outside Writable Mounts]]: policy, agent config, hooks, MCP manifests and the broker binary sit outside every writable mount.

## The incidents this layout answers

- Claude Code CVE-2025-54794/54795: a naive path-prefix check and command injection through an allowlisted `echo`; the fix class is kernel-enforced FS, not string checks ([Cymulate](https://cymulate.com/blog/cve-2025-547954-54795-claude-inverseprompt/)); see [[Claude Code Path and Command Injection CVEs]].
- Cursor "DuneSlide" (fixed April 2026): `working_directory` and a symlink fallback allowed writes to `~/.zshrc` and the sandbox helper ([The Hacker News](https://thehackernews.com/2026/07/critical-cursor-flaws-could-let-prompt.html)); CVE numbers and dates are single-source; see [[Cursor DuneSlide Sandbox Escape]].
- Copilot CVE-2025-53773 and Cursor CurXecute/MCPoison: the agent wrote `.vscode/settings.json` or `.cursor/mcp.json` ([Embrace The Red](https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/); [Tenable](https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison)); see [[Copilot Auto-Approve Settings Write]] and [[Cursor CurXecute and MCPoison]].

## The deny-glob hole on Linux

- srt's Linux filesystem rules take literal paths only ([srt](https://github.com/anthropic-experimental/sandbox-runtime)); both srt and Codex use ripgrep to expand deny-globs into literal bind mounts at sandbox start (srt scans to `mandatoryDenySearchDepth`, default 3).
- Files created *after* startup that match a deny glob are therefore not covered on Linux (research note 01 inference).
- **Proposal.** Close it with allowlist semantics: [[Landlock]] grants read and write only beneath named hierarchies, so a later-created secret outside them is unreadable regardless of name; inside the writable repo, protected names are re-checked by the broker before push (a hook or `.git/config` change never leaves the machine through the broker). fanotify or a FUSE/virtiofs policy layer are the heavier options named in the research notes.
- On macOS, SBPL supports globs and subpath rules directly ([srt](https://github.com/anthropic-experimental/sandbox-runtime)).

## Copy-on-write rollback

**Proposal** (report). Offer rollback through a CoW layer so changes reach the real repo only through a reviewed merge.

| Platform | Mechanism | Commit | Rollback |
|---|---|---|---|
| Linux (standard tier) | overlayfs, lower = repo, upper = per-session dir, mounted inside the user namespace | diff or merge the upper dir | delete the upper dir |
| macOS (standard tier) | APFS `clonefile` copy of the repo; Seatbelt write-allow only on the clone | merge the clone | delete the clone |
| VMs | qcow2/ext4 CoW disk, or the Firecracker snapshot | merge from the guest | discard the disk |

Precedent: Docker Sandboxes' clone mode mounts the host source read-only at `/run/sandbox/source` and the agent works on a private clone; it also offers a direct virtiofs mount at the same absolute path with caching on, and a mountless mode ([Docker architecture](https://docs.docker.com/ai/sandboxes/architecture/)). Docker sbx cannot mask individual files inside the project folder ([INNOQ](https://www.innoq.com/en/blog/2026/07/trust-but-sandbox/)), which the broker's per-path rules can.

> [!question] Unverified
> The kernel version that enables unprivileged overlayfs inside a user namespace (believed ≥5.11, background knowledge) and APFS `clonefile` behaviour for the macOS clone mode are **not verified** in the record. Verify both before the rollback mode ships ([[Open Questions and Unverified Claims]]).

## VM file sharing

- Lima: virtiofs by default on VZ, 9p on QEMU (Lima ≥1.0); WSL2's 9P-based sharing performs "similar to Lima's 9p mode" ([Lima docs](https://lima-vm.io/docs/config/mount/)).
- virtio-fs merged in Linux 5.4 with better performance than virtio-9p (background) ([Phoronix](https://www.phoronix.com/news/Linux-5.4-VirtIO-FS)).
- libkrun warns virtio-fs "doesn't protect against cross-directory access within the same filesystem" ([libkrun](https://github.com/containers/libkrun)): share the repo directory alone, never a parent.
- Firecracker has no shared filesystem; it exposes block devices ([Firecracker SPECIFICATION.md](https://github.com/firecracker-microvm/firecracker/blob/main/SPECIFICATION.md)).
- No 2025–2026 benchmark of virtiofs vs 9p vs gRPC-FUSE on Apple silicon exists in the record.

## Verdict for the broker

**Proposal.**

- **Use it for:** one FS policy model (Cedar `Dir`/`File` resources) compiled to every backend; mount the repo, not `$HOME`; protected subpaths read-only; CoW rollback as an opt-in mode after M0.
- **Don't use it for:** string-prefix path checks in user space (the CVE-2025-54794 class); deny-glob-only protection on Linux.
- **How we integrate it.** An FS compiler in `crates/policy` emits (a) SBPL fragments, (b) bwrap argument lists, (c) Landlock rulesets, all from one canonical path set; paths are canonicalised (symlinks resolved, `..` rejected) before compilation, with the same discipline as [[I6 Single Canonicaliser]]. [[Sandbox Launcher]] applies them; the overlayfs mode lives in the `linux-native` backend behind a probe for unprivileged overlayfs support.

## How it connects

- delivered-by:: [[Sandbox Launcher]]
- implements:: [[I5 Config Outside Writable Mounts]]
- implements:: [[I1 No Secrets in the Sandbox]] (secret dirs never readable)
- depends-on:: [[Landlock]] (allowlist rules close the glob hole)
- depends-on:: [[bubblewrap]] (bind layout)
- depends-on:: [[Seatbelt]] (SBPL path rules)
- example-of:: [[Docker Sandboxes]] (clone mode precedent)
- depends-on:: [[Git Smart-HTTP Adapter]] (agent commits, broker pushes)
- mitigates:: [[Cursor DuneSlide Sandbox Escape]]
- mitigates:: [[Claude Code Path and Command Injection CVEs]]
- mitigates:: [[Copilot Auto-Approve Settings Write]]
- mitigates:: [[Cursor CurXecute and MCPoison]]
- depends-on:: [[broker.toml Human Policy Layer]] (`filesystem.*` keys)

## Implications for the build

- M0: reading `~/.ssh/id_ed25519` is denied on every OS ([[M0 Contained Run]]).
- Conformance category 10: secret-path reads; writes outside grants; symlink, hardlink and `..` traversal; writes to rc files, git hooks and agent config; rename TOCTOU; all kernel-denied ([[Conformance Probe Matrix]]).
- Add a test that creates a new file matching a deny glob *after* start and proves it is unreadable.

## Open questions

- Unprivileged overlayfs kernel version, APFS clone behaviour, virtiofs vs 9p numbers ([[Open Questions and Unverified Claims]]).

## Sources

See `sources:` in the frontmatter; every URL is cited inline above.
