// SPDX-License-Identifier: Apache-2.0
//
// The audited syscall shims (ADR-0027/ADR-0028): the ONLY unsafe
// code in ogir-agent. The crate's single gate-enforced
// audited-allow attribute sits on the `mod audited`
// declaration in lib.rs (scripts/test-mock-substrate.py counts
// exactly one). Each function performs one libc call on locals with
// a written safety argument; there is no other unsafe anywhere in
// the crate.

/// Reads the kernel-reported credentials of a connected peer via
/// SO_PEERCRED (ADR-0027).
///
/// # Safety
///
/// Exactly one `getsockopt` call for the fixed options
/// `SOL_SOCKET`/`SO_PEERCRED` writing at most `*length` bytes into
/// the caller's buffer (the kernel writes one `struct ucred` when
/// the buffer is at least that large). The descriptor must belong
/// to a live connected Unix socket.
pub fn getsockopt_peer_cred(socket: i32, value: *mut core::ffi::c_void, length: *mut u32) -> i32 {
    const SOL_SOCKET: i32 = 1;
    const SO_PEERCRED: i32 = 17;
    // SAFETY: the declaration is local and call-compatible; see the
    // function-level safety argument above.
    unsafe extern "C" {
        fn getsockopt(
            socket: i32,
            level: i32,
            name: i32,
            value: *mut core::ffi::c_void,
            length: *mut u32,
        ) -> i32;
    }
    // SAFETY: one call, caller-owned buffer, fixed options (above).
    unsafe { getsockopt(socket, SOL_SOCKET, SO_PEERCRED, value, length) }
}

// x86_64 syscall numbers (the M5 platform is x86_64).
const SYS_PIDFD_OPEN: i64 = 434;
const SYS_PIDFD_SEND_SIGNAL: i64 = 424;

unsafe extern "C" {
    fn syscall(number: i64, ...) -> i64;
}

/// Opens a pidfd for `pid` (ADR-0028). Returns the raw descriptor
/// or -1 with errno set.
///
/// # Safety
///
/// Exactly one `syscall(SYS_pidfd_open, pid, flags)` call with two
/// integer by-value arguments; the kernel returns a small integer.
/// No pointers are passed at all.
pub fn pidfd_open(pid: u32, flags: u32) -> i32 {
    // SAFETY: see the function-level safety argument above.
    unsafe { syscall(SYS_PIDFD_OPEN, i64::from(pid), i64::from(flags)) as i32 }
}

/// Probes a pidfd's process with signal 0 (liveness only). Returns
/// 0 when the signal was deliverable, -1 with errno otherwise
/// (ESRCH once the process has exited).
///
/// # Safety
///
/// Exactly one `syscall(SYS_pidfd_send_signal, pidfd, 0, NULL)`
/// call: an integer descriptor, the null signal, and a NULL pointer
/// the kernel does not write through for signal 0.
pub fn pidfd_send_signal_zero(pidfd: i32) -> i32 {
    // SAFETY: see the function-level safety argument above.
    unsafe {
        syscall(
            SYS_PIDFD_SEND_SIGNAL,
            i64::from(pidfd),
            0,
            core::ptr::null_mut::<core::ffi::c_void>(),
            0,
        ) as i32
    }
}

/// Closes a raw descriptor.
///
/// # Safety
///
/// Exactly one `close(fd)` call on an owned descriptor that the
/// caller will not use again.
pub fn close_fd(fd: i32) -> i32 {
    // SAFETY: the declaration is local and call-compatible.
    unsafe extern "C" {
        fn close(fd: i32) -> i32;
    }
    // SAFETY: one call on an owned descriptor (above).
    unsafe { close(fd) }
}
