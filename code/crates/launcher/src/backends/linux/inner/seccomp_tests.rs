//! The filters, evaluated by a small classic-BPF interpreter under the
//! kernel's precedence rule (ADR-043): moving the deny filter to
//! `USER_NOTIF` changes how a refusal is delivered, never whether a
//! syscall is refused, with brokerd answering or not.

use super::*;
use seccompiler::sock_filter;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7; // AUDIT_ARCH_AARCH64

/// SECCOMP_RET_ACTION_FULL.
const ACTION: u32 = 0xffff_0000;

/// Run one program over (nr, arch, args) laid out as `struct seccomp_data`.
fn run(prog: &[sock_filter], nr: i64, arch: u32, args: &[u64; 6]) -> u32 {
    let mut data = [0u8; 64];
    data[0..4].copy_from_slice(&(nr as i32).to_ne_bytes());
    data[4..8].copy_from_slice(&arch.to_ne_bytes());
    for (i, a) in args.iter().enumerate() {
        data[16 + 8 * i..24 + 8 * i].copy_from_slice(&a.to_ne_bytes());
    }
    let (mut pc, mut acc) = (0usize, 0u32);
    // Classic BPF jumps only forward, so a program runs at most len steps.
    for _ in 0..=prog.len() {
        let i = &prog[pc];
        let jump = |c: bool| 1 + if c { i.jt } else { i.jf } as usize;
        pc += match i.code {
            0x20 => {
                let k = i.k as usize; // BPF_LD | BPF_W | BPF_ABS
                acc = u32::from_ne_bytes(data[k..k + 4].try_into().unwrap());
                1
            }
            0x54 => {
                acc &= i.k; // BPF_ALU | BPF_AND | BPF_K
                1
            }
            0x05 => 1 + i.k as usize, // BPF_JMP | BPF_JA
            0x15 => jump(acc == i.k), // JEQ
            0x25 => jump(acc > i.k),  // JGT
            0x35 => jump(acc >= i.k), // JGE
            0x45 => jump(acc & i.k != 0),
            0x06 => return i.k, // BPF_RET | BPF_K
            c => panic!("opcode {c:#x} at {pc}"),
        };
    }
    panic!("the program did not return");
}

/// The kernel's verdict over filters installed in this order: newest first,
/// the lowest signed action wins, a tie keeps the newer filter's value.
fn verdict(installed: &[BpfProgram], nr: i64, args: &[u64; 6]) -> u32 {
    let mut ret = libc::SECCOMP_RET_ALLOW;
    for p in installed.iter().rev() {
        let r = run(p, nr, AUDIT_ARCH, args);
        if ((r & ACTION) as i32) < ((ret & ACTION) as i32) {
            ret = r;
        }
    }
    ret
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Outcome {
    Allowed,
    Errno(i32),
    Killed,
}

/// What the caller sees. `served`: brokerd holds the listener and answers
/// (always EPERM); unserved, the kernel answers ENOSYS.
fn outcome(v: u32, served: bool) -> Outcome {
    match v & ACTION {
        libc::SECCOMP_RET_ALLOW => Outcome::Allowed,
        libc::SECCOMP_RET_ERRNO => Outcome::Errno((v & 0xffff) as i32),
        libc::SECCOMP_RET_USER_NOTIF => Outcome::Errno(if served { libc::EPERM } else { libc::ENOSYS }),
        libc::SECCOMP_RET_KILL_PROCESS => Outcome::Killed,
        other => panic!("unexpected action {other:#x}"),
    }
}

struct Sets {
    /// ADR-018 as built before ADR-043.
    old: Vec<BpfProgram>,
    /// What `apply(true)` installs: clone3, x32, then the deny filter with a listener.
    notify: Vec<BpfProgram>,
    /// What it installs when the kernel gives no listener.
    fallback: Vec<BpfProgram>,
}

fn sets() -> Sets {
    let mut notify = enosys_filters().unwrap();
    notify.push(notify_filter().unwrap());
    notify.push(fixed_filter().unwrap());
    let mut fallback = enosys_filters().unwrap();
    fallback.push(eperm_filter().unwrap());
    fallback.push(fixed_filter().unwrap());
    Sets { old: build().unwrap(), notify, fallback }
}

/// Arguments that exercise every rule and its near misses.
fn arg_grid() -> Vec<[u64; 6]> {
    let mut a0: Vec<u64> = [0, libc::AF_UNIX, libc::AF_INET, libc::AF_INET6, libc::AF_PACKET, libc::AF_NETLINK]
        .iter()
        .map(|v| *v as u64)
        .collect();
    a0.extend(CLONE_NS_FLAGS.iter().map(|f| (*f | libc::SIGCHLD) as u64));
    a0.extend([
        libc::SIGCHLD as u64,
        (libc::CLONE_VM | libc::CLONE_FS | libc::CLONE_FILES | libc::CLONE_SIGHAND | libc::CLONE_THREAD) as u64,
        (libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD) as u64,
        (1u64 << 32) | libc::AF_UNIX as u64,
        u64::MAX,
    ]);
    let a1: Vec<u64> = vec![
        0,
        libc::SOCK_STREAM as u64,
        libc::SOCK_DGRAM as u64,
        libc::SOCK_RAW as u64,
        (libc::SOCK_RAW | libc::SOCK_CLOEXEC) as u64,
        (libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) as u64,
        libc::TIOCSTI,
        libc::TIOCLINUX,
        libc::TCGETS,
        libc::FIONREAD,
    ];
    let mut out = Vec::new();
    for x in &a0 {
        for y in &a1 {
            out.push([*x, *y, 0, 0, 0, 0]);
        }
    }
    out
}

/// The patched program is the same program but for the match action.
#[test]
fn notify_filter_differs_from_the_eperm_filter_only_in_its_match_action() {
    let (p, n) = (eperm_filter().unwrap(), notify_filter().unwrap());
    assert_eq!(p.len(), n.len());
    let mut patched = 0;
    for (a, b) in p.iter().zip(&n) {
        if a == b {
            continue;
        }
        assert_eq!((a.code, a.k, b.k), (RET_K, RET_EPERM, libc::SECCOMP_RET_USER_NOTIF), "{a:?} -> {b:?}");
        assert_eq!((a.jt, a.jf), (b.jt, b.jf));
        patched += 1;
    }
    assert!(patched > 0);
    assert!(!n.iter().any(|i| i.code == RET_K && i.k == RET_EPERM), "no EPERM return left");
    for nr in 0..=470 {
        for args in arg_grid() {
            let (rp, rn) = (run(&p, nr, AUDIT_ARCH, &args), run(&n, nr, AUDIT_ARCH, &args));
            if rp == RET_EPERM {
                assert_eq!(rn, libc::SECCOMP_RET_USER_NOTIF, "nr {nr} {args:?}");
            } else {
                assert_eq!(rn, rp, "nr {nr} {args:?}");
            }
        }
    }
}

/// No syscall becomes allowed: whatever the old filters refused is refused
/// by the new ones, with EPERM when brokerd answers and ENOSYS when it does
/// not; whatever they allowed stays allowed; the fallback is the old set.
#[test]
fn no_syscall_becomes_allowed_with_or_without_brokerd() {
    let s = sets();
    for nr in 0..=470 {
        for args in arg_grid() {
            let old = outcome(verdict(&s.old, nr, &args), true);
            let served = outcome(verdict(&s.notify, nr, &args), true);
            let unserved = outcome(verdict(&s.notify, nr, &args), false);
            let fallback = outcome(verdict(&s.fallback, nr, &args), true);
            assert_eq!(served, old, "nr {nr} {args:?}");
            assert_eq!(fallback, old, "nr {nr} {args:?}");
            match old {
                Outcome::Errno(libc::EPERM) => assert_eq!(unserved, Outcome::Errno(libc::ENOSYS), "nr {nr}"),
                other => assert_eq!(unserved, other, "nr {nr} {args:?}"),
            }
        }
    }
}

/// Every syscall `denied_syscalls()` lists, and every argument rule, is
/// refused: EPERM answered by brokerd, ENOSYS without it, EPERM with the
/// fallback filter.
#[test]
fn every_listed_syscall_is_refused() {
    let s = sets();
    let mut cases: Vec<(i64, [u64; 6])> = denied_syscalls().into_iter().map(|nr| (nr, [0; 6])).collect();
    let sock = |d: i32, t: i32| (libc::SYS_socket, [d as u64, t as u64, 0, 0, 0, 0]);
    cases.extend([
        sock(libc::AF_UNIX, libc::SOCK_STREAM),
        sock(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC),
        sock(libc::AF_PACKET, libc::SOCK_RAW),
        sock(libc::AF_INET, libc::SOCK_RAW),
        sock(libc::AF_INET6, libc::SOCK_RAW | libc::SOCK_NONBLOCK),
        (libc::SYS_ioctl, [0, libc::TIOCSTI, 0, 0, 0, 0]),
        (libc::SYS_ioctl, [0, libc::TIOCLINUX, 0, 0, 0, 0]),
    ]);
    cases.extend(CLONE_NS_FLAGS.iter().map(|f| (libc::SYS_clone, [(*f | libc::SIGCHLD) as u64, 0, 0, 0, 0, 0])));
    for (nr, args) in cases {
        assert_eq!(outcome(verdict(&s.old, nr, &args), true), Outcome::Errno(libc::EPERM), "old {nr} {args:?}");
        assert_eq!(outcome(verdict(&s.notify, nr, &args), true), Outcome::Errno(libc::EPERM), "{nr} {args:?}");
        assert_eq!(outcome(verdict(&s.notify, nr, &args), false), Outcome::Errno(libc::ENOSYS), "{nr} {args:?}");
        assert_eq!(outcome(verdict(&s.fallback, nr, &args), true), Outcome::Errno(libc::EPERM), "{nr} {args:?}");
        assert_eq!(verdict(&s.notify, nr, &args) & ACTION, libc::SECCOMP_RET_USER_NOTIF, "recorded: {nr}");
    }
}

/// What was allowed or ENOSYS before stays so, and is never notified.
#[test]
fn controls_keep_their_action() {
    let s = sets();
    let allowed: Vec<(i64, [u64; 6])> = vec![
        (libc::SYS_socket, [libc::AF_INET as u64, libc::SOCK_STREAM as u64, 0, 0, 0, 0]),
        (libc::SYS_socket, [libc::AF_INET6 as u64, libc::SOCK_DGRAM as u64, 0, 0, 0, 0]),
        (libc::SYS_socket, [libc::AF_NETLINK as u64, libc::SOCK_RAW as u64, 0, 0, 0, 0]),
        (libc::SYS_socketpair, [libc::AF_UNIX as u64, libc::SOCK_STREAM as u64, 0, 0, 0, 0]),
        (libc::SYS_clone, [libc::SIGCHLD as u64, 0, 0, 0, 0, 0]),
        (libc::SYS_ioctl, [0, libc::TCGETS, 0, 0, 0, 0]),
        (libc::SYS_getpid, [0; 6]),
        (libc::SYS_seccomp, [0; 6]),
    ];
    for (nr, args) in allowed {
        for set in [&s.old, &s.notify, &s.fallback] {
            assert_eq!(outcome(verdict(set, nr, &args), false), Outcome::Allowed, "{nr} {args:?}");
        }
    }
    // ADR-045: no listener of the agent's own, no datagram socket pairs;
    // refused with ERRNO in every set, so they outrank any USER_NOTIF.
    let new_listener = u64::from(libc::SECCOMP_FILTER_FLAG_NEW_LISTENER as u32);
    let filter_mode = u64::from(libc::SECCOMP_SET_MODE_FILTER);
    let refused: Vec<(i64, [u64; 6])> = vec![
        (libc::SYS_seccomp, [filter_mode, new_listener, 0, 0, 0, 0]),
        (libc::SYS_seccomp, [filter_mode, new_listener | 1, 0, 0, 0, 0]),
        (libc::SYS_seccomp, [filter_mode | (1 << 32), new_listener | (7 << 40), 0, 0, 0, 0]),
        (libc::SYS_socketpair, [libc::AF_UNIX as u64, libc::SOCK_DGRAM as u64, 0, 0, 0, 0]),
        (libc::SYS_socketpair, [libc::AF_UNIX as u64, (libc::SOCK_DGRAM | libc::SOCK_CLOEXEC) as u64, 0, 0, 0, 0]),
    ];
    for (nr, args) in refused {
        for set in [&s.old, &s.notify, &s.fallback] {
            for served in [true, false] {
                assert_eq!(outcome(verdict(set, nr, &args), served), Outcome::Errno(libc::EPERM), "{nr} {args:?}");
            }
        }
    }
    for (nr, args) in [
        (libc::SYS_seccomp, [filter_mode, 0, 0, 0, 0, 0]),
        (libc::SYS_socketpair, [libc::AF_UNIX as u64, libc::SOCK_SEQPACKET as u64, 0, 0, 0, 0]),
    ] {
        for set in [&s.old, &s.notify, &s.fallback] {
            assert_eq!(outcome(verdict(set, nr, &args), false), Outcome::Allowed, "{nr} {args:?}");
        }
    }
    for set in [&s.old, &s.notify, &s.fallback] {
        assert_eq!(outcome(verdict(set, libc::SYS_clone3, &[0; 6]), false), Outcome::Errno(libc::ENOSYS));
        #[cfg(target_arch = "x86_64")]
        assert_eq!(
            outcome(verdict(set, 0x4000_0000 | libc::SYS_socket, &[1, 1, 0, 0, 0, 0]), false),
            Outcome::Errno(libc::ENOSYS)
        );
        // A foreign architecture's calling convention (i386) is killed.
        let foreign = set.iter().map(|p| run(p, libc::SYS_getpid, 0x4000_0003, &[0; 6]));
        assert_eq!(foreign.min_by_key(|r| (r & ACTION) as i32), Some(libc::SECCOMP_RET_KILL_PROCESS));
    }
}

proptest::proptest! {
    /// Over random numbers and registers, the new sets refuse exactly what
    /// the old one refuses.
    #[test]
    fn refusals_are_unchanged_for_any_registers(
        nr in 0i64..1024,
        args in proptest::array::uniform6(proptest::num::u64::ANY),
    ) {
        let s = sets();
        let old = outcome(verdict(&s.old, nr, &args), true);
        proptest::prop_assert_eq!(outcome(verdict(&s.notify, nr, &args), true), old);
        proptest::prop_assert_eq!(outcome(verdict(&s.fallback, nr, &args), true), old);
        let unserved = outcome(verdict(&s.notify, nr, &args), false);
        proptest::prop_assert_eq!(unserved == Outcome::Allowed, old == Outcome::Allowed);
    }
}
