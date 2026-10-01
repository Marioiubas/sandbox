//! Names and plain arguments of the syscalls the deny filter refuses, for
//! the record (ADR-043). Only register values are named here, never an
//! argument that is a pointer into the caller's memory: brokerd never reads
//! through one, so nothing on the record can be changed by the sandbox
//! between the check and the read.

/// Low 32 bits (the kernel reads `int` and `unsigned int` arguments so).
const M32: u64 = 0xffff_ffff;
const M64: u64 = u64::MAX;

type Plain = &'static [(&'static str, usize, u64)];

/// The syscall's name and its plain arguments (name, value). Total: an
/// unknown number is `"unknown"` with no arguments.
pub fn describe(nr: i64, args: &[u64; 6]) -> (&'static str, Vec<(&'static str, u64)>) {
    let (name, plain): (&'static str, Plain) = match nr {
        libc::SYS_socket => ("socket", &[("domain", 0, M32), ("type", 1, M32), ("protocol", 2, M32)]),
        libc::SYS_clone => ("clone", &[("flags", 0, M64)]),
        libc::SYS_ioctl => ("ioctl", &[("fd", 0, M32), ("request", 1, M32)]),
        libc::SYS_ptrace => ("ptrace", &[("request", 0, M64), ("target_pid", 1, M32)]),
        libc::SYS_process_vm_readv => ("process_vm_readv", &[("target_pid", 0, M32)]),
        libc::SYS_process_vm_writev => ("process_vm_writev", &[("target_pid", 0, M32)]),
        libc::SYS_bpf => ("bpf", &[("cmd", 0, M32)]),
        libc::SYS_perf_event_open => ("perf_event_open", &[("target_pid", 1, M32), ("cpu", 2, M32), ("flags", 4, M64)]),
        libc::SYS_keyctl => ("keyctl", &[("operation", 0, M32)]),
        libc::SYS_add_key => ("add_key", &[("keyring", 4, M32)]),
        libc::SYS_request_key => ("request_key", &[("keyring", 3, M32)]),
        libc::SYS_mount => ("mount", &[("flags", 3, M64)]),
        libc::SYS_umount2 => ("umount2", &[("flags", 1, M32)]),
        libc::SYS_pivot_root => ("pivot_root", &[]),
        libc::SYS_unshare => ("unshare", &[("flags", 0, M32)]),
        libc::SYS_setns => ("setns", &[("fd", 0, M32), ("nstype", 1, M32)]),
        libc::SYS_io_uring_setup => ("io_uring_setup", &[("entries", 0, M32)]),
        libc::SYS_io_uring_enter => ("io_uring_enter", &[("fd", 0, M32)]),
        libc::SYS_io_uring_register => ("io_uring_register", &[("fd", 0, M32), ("opcode", 1, M32)]),
        libc::SYS_open_by_handle_at => ("open_by_handle_at", &[("mount_fd", 0, M32), ("flags", 2, M32)]),
        libc::SYS_kexec_load => ("kexec_load", &[("flags", 3, M64)]),
        libc::SYS_init_module => ("init_module", &[]),
        libc::SYS_finit_module => ("finit_module", &[("fd", 0, M32), ("flags", 2, M32)]),
        libc::SYS_delete_module => ("delete_module", &[("flags", 1, M32)]),
        libc::SYS_userfaultfd => ("userfaultfd", &[("flags", 0, M32)]),
        libc::SYS_fanotify_init => ("fanotify_init", &[("flags", 0, M32), ("event_f_flags", 1, M32)]),
        _ => ("unknown", &[]),
    };
    (name, plain.iter().map(|(k, i, m)| (*k, args[*i] & m)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::linux::inner::seccomp::denied_syscalls;

    #[test]
    fn every_denied_syscall_has_a_name() {
        let mut all = denied_syscalls();
        all.extend([libc::SYS_socket, libc::SYS_clone, libc::SYS_ioctl]);
        for nr in all {
            assert_ne!(describe(nr, &[0; 6]).0, "unknown", "syscall {nr}");
        }
        let a = [libc::AF_UNIX as u64 | 0xdead_0000_0000, libc::SOCK_STREAM as u64, 0, 9, 9, 9];
        assert_eq!(describe(libc::SYS_socket, &a), ("socket", vec![("domain", 1), ("type", 1), ("protocol", 0)]));
        let flags = libc::CLONE_NEWUSER as u64 | 0x1_0000_0000;
        assert_eq!(describe(libc::SYS_clone, &[flags, 0, 0, 0, 0, 0]).1, vec![("flags", flags)]);
        assert_eq!(describe(libc::SYS_getpid, &[0; 6]), ("unknown", vec![]));
    }

    proptest::proptest! {
        /// Total over any number and registers; names only plain arguments.
        #[test]
        fn describe_is_total(nr in proptest::num::i64::ANY, args in proptest::array::uniform6(proptest::num::u64::ANY)) {
            let (name, plain) = describe(nr, &args);
            proptest::prop_assert!(!name.is_empty());
            proptest::prop_assert!(plain.len() <= 6);
            for (k, v) in plain {
                proptest::prop_assert!(!k.is_empty());
                proptest::prop_assert!(args.iter().any(|a| *a & v == v));
            }
        }
    }
}
