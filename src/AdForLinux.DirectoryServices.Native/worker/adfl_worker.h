#ifndef ADFL_WORKER_H
#define ADFL_WORKER_H
#if defined(__GNUC__)
#define ADFL_WORKER_API __attribute__((visibility("default")))
#else
#define ADFL_WORKER_API
#endif
#ifdef __cplusplus
extern "C" {
#endif
/* Linux/glibc supervisor ABI. All status returns are 0 or positive errno.
 * No LDAP, authentication, shell, global environment or numeric-PID signaling.
 * Spawn may block: caller must isolate it from its operation deadline thread. */
ADFL_WORKER_API unsigned adfl_worker_abi_version(void);
ADFL_WORKER_API int adfl_worker_spawn(const char *, const char *const *, const char *const *, int *, int *);
ADFL_WORKER_API int adfl_worker_child_send_identity(int);
/* EAGAIN means no identity yet. Output owns one CLOEXEC pidfd on success. */
ADFL_WORKER_API int adfl_worker_parent_receive_identity(int, int expected_spawn_pid, int *);
ADFL_WORKER_API int adfl_worker_signal_kill(int);
/* Zero proves exit (including another reaper with pidfd exit readiness).
 * EAGAIN means still running; ECHILD without readiness is unverified.
 * Never waits for exit. Caller retains pidfd until reaping or explicit handoff. */
ADFL_WORKER_API int adfl_worker_reap_nonblocking(int);
ADFL_WORKER_API int adfl_worker_closefd(int);
#ifdef __cplusplus
}
#endif
#endif
