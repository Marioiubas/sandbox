//! The seccomp filters (see the seccomp-bpf note, ADR-018 and ADR-043).
//!
//! - The **deny filter**: every rule of ADR-018 (new AF_UNIX, packet and raw
//!   sockets, ptrace, bpf, keyctl, mount, namespaces, io_uring, ...). When the
//!   kernel can hand a listener to brokerd its match action is `USER_NOTIF`,
//!   and brokerd answers every notification `-EPERM` and records it; else it
//!   is `ERRNO(EPERM)`, exactly the filter of ADR-018. The two programs are
//!   the same instructions except for that return value
//!   ([`to_user_notif`]), so they match the same syscalls and arguments.
//! - `clone3` → ENOSYS (libc falls back to `clone`, whose flags the deny
//!   filter reads), and on x86_64 every x32 syscall number → ENOSYS. These
//!   keep their action and are not recorded.
//!
//! Precedence: the kernel runs every filter and takes the most restrictive
//! action (KILL > TRAP > ERRNO > USER_NOTIF > TRACE > LOG > ALLOW). An ERRNO
//! rule for a syscall would therefore silence its notification, which is
//! why the deny filter is installed in one form or the other, never both.

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen as Len, SeccompCmpOp as Op, SeccompCondition as Cond, SeccompFilter,
    SeccompRule, TargetArch,
};
use std::collections::BTreeMap;
use std::io;
use std::os::fd::OwnedFd;

/// `BPF_RET | BPF_K`.
const RET_K: u16 = 0x06;
/// The deny filter's match action without a listener.
const RET_EPERM: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;

fn arch() -> anyhow::Result<TargetArch> {
    Ok(std::env::consts::ARCH.try_into()?)
}

fn eq(arg: u8, v: u64) -> Cond {
    Cond::new(arg, Len::Dword, Op::Eq, v).expect("valid condition")
}

fn bits(arg: u8, mask: u64) -> Cond {
    Cond::new(arg, Len::Qword, Op::MaskedEq(mask), mask).expect("valid condition")
}

/// Syscalls denied outright, whatever their arguments.
pub fn denied_syscalls() -> Vec<i64> {
    vec![
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_open_by_handle_at,
        libc::SYS_kexec_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_userfaultfd,
        libc::SYS_fanotify_init,
    ]
}

/// Namespace flags `clone` may not carry.
pub const CLONE_NS_FLAGS: [i32; 7] = [
    libc::CLONE_NEWUSER,
    libc::CLONE_NEWNS,
    libc::CLONE_NEWNET,
    libc::CLONE_NEWPID,
    libc::CLONE_NEWIPC,
    libc::CLONE_NEWUTS,
    libc::CLONE_NEWCGROUP,
];

/// Every rule of the deny filter. Each is decided by the syscall number or
/// by plain register arguments (a filter cannot read through pointers).
fn rules() -> anyhow::Result<BTreeMap<i64, Vec<SeccompRule>>> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for s in denied_syscalls() {
        rules.insert(s, vec![]);
    }
    // socket(): no new AF_UNIX (ctl.sock, docker.sock and every other host
    // socket stay unreachable), no packet sockets, no raw sockets.
    // socketpair(AF_UNIX) stays allowed: an anonymous pair cannot reach a
    // named socket, and Node's child_process needs it (ADR-018).
    let sock_type_mask = 0xf;
    rules.insert(
        libc::SYS_socket,
        vec![
            SeccompRule::new(vec![eq(0, libc::AF_UNIX as u64)])?,
            SeccompRule::new(vec![eq(0, libc::AF_PACKET as u64)])?,
            SeccompRule::new(vec![
                eq(0, libc::AF_INET as u64),
                Cond::new(1, Len::Dword, Op::MaskedEq(sock_type_mask), libc::SOCK_RAW as u64)?,
            ])?,
            SeccompRule::new(vec![
                eq(0, libc::AF_INET6 as u64),
                Cond::new(1, Len::Dword, Op::MaskedEq(sock_type_mask), libc::SOCK_RAW as u64)?,
            ])?,
        ],
    );
    // No new namespaces via clone flags.
    rules.insert(
        libc::SYS_clone,
        CLONE_NS_FLAGS.iter().map(|f| SeccompRule::new(vec![bits(0, *f as u64)])).collect::<Result<_, _>>()?,
    );
    // Terminal input injection into the user's shell.
    rules.insert(
        libc::SYS_ioctl,
        vec![SeccompRule::new(vec![eq(1, libc::TIOCSTI)])?, SeccompRule::new(vec![eq(1, libc::TIOCLINUX)])?],
    );
    Ok(rules)
}

/// The deny filter with `ERRNO(EPERM)`: ADR-018's filter, installed when
/// the kernel cannot give brokerd a listener.
pub fn eperm_filter() -> anyhow::Result<BpfProgram> {
    Ok(SeccompFilter::new(rules()?, SeccompAction::Allow, SeccompAction::Errno(libc::EPERM as u32), arch()?)?
        .try_into()?)
}

/// The same program with every `ERRNO(EPERM)` return turned into
/// `USER_NOTIF`: only that return value changes, so the same syscalls and
/// arguments match. The arch check (KILL) and the default (ALLOW) are other
/// return values and stay as they are.
pub fn to_user_notif(mut p: BpfProgram) -> anyhow::Result<BpfProgram> {
    let mut n = 0;
    for ins in p.iter_mut().filter(|i| i.code == RET_K && i.k == RET_EPERM) {
        ins.k = libc::SECCOMP_RET_USER_NOTIF;
        n += 1;
    }
    anyhow::ensure!(n > 0, "the deny filter has no EPERM return");
    Ok(p)
}

/// The deny filter with `USER_NOTIF` (ADR-043).
pub fn notify_filter() -> anyhow::Result<BpfProgram> {
    to_user_notif(eperm_filter()?)
}

/// The filters whose action does not depend on brokerd: clone3 and x32.
pub fn enosys_filters() -> anyhow::Result<Vec<BpfProgram>> {
    // clone3 passes flags in memory the filter cannot read: ENOSYS makes
    // libc fall back to clone(), which the deny filter can inspect.
    let mut c3: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    c3.insert(libc::SYS_clone3, vec![]);
    let enosys: BpfProgram =
        SeccompFilter::new(c3, SeccompAction::Allow, SeccompAction::Errno(libc::ENOSYS as u32), arch()?)?.try_into()?;
    #[allow(unused_mut)]
    let mut progs = vec![enosys];
    #[cfg(target_arch = "x86_64")]
    progs.push(x32_filter());
    Ok(progs)
}

/// ADR-018's filter set (the deny filter with EPERM, clone3, x32).
pub fn build() -> anyhow::Result<Vec<BpfProgram>> {
    let mut progs = vec![eperm_filter()?];
    progs.extend(enosys_filters()?);
    Ok(progs)
}

/// x86_64 only: refuse the x32 ABI (syscall numbers with bit 30 set),
/// which would otherwise bypass rules keyed on x86_64 numbers.
#[cfg(target_arch = "x86_64")]
fn x32_filter() -> BpfProgram {
    use seccompiler::sock_filter;
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JGE_K: u16 = 0x35;
    const X32_BIT: u32 = 0x4000_0000;
    const RET_ALLOW: u32 = 0x7fff_0000;
    let ret_errno = 0x0005_0000 | libc::ENOSYS as u32;
    vec![
        sock_filter { code: BPF_LD_W_ABS, jt: 0, jf: 0, k: 0 }, // seccomp_data.nr
        sock_filter { code: BPF_JGE_K, jt: 0, jf: 1, k: X32_BIT },
        sock_filter { code: RET_K, jt: 0, jf: 0, k: ret_errno },
        sock_filter { code: RET_K, jt: 0, jf: 0, k: RET_ALLOW },
    ]
}

/// How the deny filter went in.
#[derive(Debug)]
pub enum Installed {
    /// With `USER_NOTIF`; the listener must reach brokerd before the shim
    /// makes any notified syscall, and then be closed.
    Notify(OwnedFd),
    /// With `ERRNO(EPERM)` (ADR-018): the kernel refused a listener (the
    /// error), or none was asked for (no channel to brokerd).
    Errno(Option<io::Error>),
}

/// Install the filters (see [`install`]).
pub fn apply(notify: bool) -> anyhow::Result<Installed> {
    let enosys = enosys_filters()?;
    let deny_notify = if notify { Some(notify_filter()?) } else { None };
    Ok(install(&enosys, deny_notify.as_ref(), &eperm_filter()?)?)
}

/// Install `enosys`, then the deny filter last: `notify` with a listener
/// if given and the kernel agrees, else `eperm`. Order matters for the shim
/// only, not for any verdict (the kernel takes the most restrictive action
/// whatever the order): once the deny filter has a listener, a notified
/// syscall by the shim would wait for an answer that only comes after the
/// shim has handed the listener over, so nothing is installed after it and
/// the shim's next calls are `sendmsg` and `close`. If the kernel refuses a
/// listener (Linux < 5.0, or another listener already on this filter chain:
/// EBUSY), the same deny filter goes in with EPERM instead: no gap, no
/// record, and the layer says so. No allocation on success (tests run it
/// between fork and exit).
pub fn install(enosys: &[BpfProgram], notify: Option<&BpfProgram>, eperm: &BpfProgram) -> io::Result<Installed> {
    let to_io = |e: seccompiler::Error| match e {
        seccompiler::Error::Seccomp(e) | seccompiler::Error::Prctl(e) => e,
        other => io::Error::other(other),
    };
    for p in enosys {
        seccompiler::apply_filter(p).map_err(to_io)?;
    }
    let why = match notify {
        Some(n) => match super::notify::install_listener(n) {
            Ok(fd) => return Ok(Installed::Notify(fd)),
            Err(e) => Some(e),
        },
        None => None,
    };
    seccompiler::apply_filter(eperm).map_err(to_io)?;
    Ok(Installed::Errno(why))
}

#[cfg(test)]
#[path = "seccomp_tests.rs"]
mod tests;
