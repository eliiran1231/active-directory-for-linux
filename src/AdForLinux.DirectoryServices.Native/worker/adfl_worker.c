#define _GNU_SOURCE
#include "adfl_worker.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

unsigned adfl_worker_abi_version(void) { return 2; }
int adfl_worker_closefd(int fd) {
    /* Linux releases the fd even when close reports EINTR; never retry against
     * a number another thread may already have reused. */
    if (close(fd) == 0) return 0;
    return errno;
}
static int high_fd(int fd) {
    int copy = fcntl(fd, F_DUPFD_CLOEXEC, 7);
    int saved = errno; close(fd); errno = saved; return copy;
}
#define PROFILE_MAX 32768
#define PROFILE_SEALS (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)
static int blob_create(const unsigned char *bytes, size_t length, size_t maximum, int *out) {
    if (!out) return EINVAL;
    *out = -1;
    if (length > maximum || (length && !bytes)) return EINVAL;
    int fd = (int)syscall(SYS_memfd_create, "adfl-worker-profile", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0) return errno;
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(fd, bytes + offset, length - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) { int e = written < 0 ? errno : EIO; close(fd); return e; }
        offset += (size_t)written;
    }
    if (lseek(fd, 0, SEEK_SET) < 0 || fcntl(fd, F_ADD_SEALS, PROFILE_SEALS) < 0) {
        int e = errno; close(fd); return e;
    }
    fd = high_fd(fd);
    if (fd < 0) return errno;
    *out = fd; return 0;
}
int adfl_worker_profile_create(const unsigned char *bytes, size_t length, int *out) {
    return blob_create(bytes, length, PROFILE_MAX, out);
}
int adfl_worker_credential_create(const unsigned char *bytes, size_t length, int *out) {
    if (!length) return EINVAL;
    return blob_create(bytes, length, 1048576, out);
}
static int profile_valid(int fd, int empty, size_t maximum) {
    int seals = fcntl(fd, F_GET_SEALS);
    if (seals < 0) return errno;
    if ((seals & PROFILE_SEALS) != PROFILE_SEALS) return EINVAL;
    struct stat status;
    if (fstat(fd, &status)) return errno;
    if (!S_ISREG(status.st_mode) ||
        (empty ? status.st_size != 0 : status.st_size <= 0 || status.st_size > (off_t)maximum)) return EINVAL;
    return 0;
}
static int spawn_core(const char *exe, const char *const *argv, const char *const *envp,
                      int config, int mechanisms, int credential, int *channel, int *child_pid) {
    if (!channel || !child_pid) return EINVAL;
    *channel = *child_pid = -1;
    if (!exe || exe[0] != '/' || !argv || !argv[0] || !envp ||
        (config < 0 && config != -1) || (mechanisms < 0 && mechanisms != -1) ||
        (config == -1) != (mechanisms == -1) || credential < -1 || (credential >= 0 && config < 0)) return EINVAL;
#if !defined(__GLIBC__) || !__GLIBC_PREREQ(2, 34)
    return ENOTSUP;
#else
    int sources[3] = {-1, -1, -1}, sockets[2] = {-1, -1}, rc = 0, initialized = 0;
    posix_spawn_file_actions_t actions;
    if (config >= 0) {
        /* Validate owned duplicates, never a caller fd which can be replaced.
         * All sources live above targets 0..6 before any child dup/open action. */
        sources[0] = fcntl(config, F_DUPFD_CLOEXEC, 7);
        if (sources[0] < 0) { rc = errno; goto done; }
        sources[1] = fcntl(mechanisms, F_DUPFD_CLOEXEC, 7);
        if (sources[1] < 0) { rc = errno; goto done; }
        if ((rc = profile_valid(sources[0], 0, PROFILE_MAX)) || (rc = profile_valid(sources[1], 1, PROFILE_MAX))) goto done;
    }
    if (credential >= 0) {
        sources[2] = fcntl(credential, F_DUPFD_CLOEXEC, 7);
        if (sources[2] < 0) { rc = errno; goto done; }
        if ((rc = profile_valid(sources[2], 0, 1048576))) goto done;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets)) { rc = errno; goto done; }
    sockets[0] = high_fd(sockets[0]);
    if (sockets[0] < 0) { rc = errno; goto done; }
    sockets[1] = high_fd(sockets[1]);
    if (sockets[1] < 0) { rc = errno; goto done; }
    int enabled = 1;
    if (setsockopt(sockets[0], SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) ||
        fcntl(sockets[0], F_SETFL, O_NONBLOCK)) { rc = errno; goto done; }
    rc = posix_spawn_file_actions_init(&actions);
    if (rc) goto done;
    initialized = 1;
    rc = posix_spawn_file_actions_addclose(&actions, sockets[0]);
    if (!rc) rc = posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0);
    if (!rc) rc = posix_spawn_file_actions_addopen(&actions, 1, "/dev/null", O_WRONLY, 0);
    if (!rc) rc = posix_spawn_file_actions_addopen(&actions, 2, "/dev/null", O_WRONLY, 0);
    if (!rc) rc = posix_spawn_file_actions_adddup2(&actions, sockets[1], 3);
    if (!rc && config >= 0) rc = posix_spawn_file_actions_adddup2(&actions, sources[0], 4);
    if (!rc && config >= 0) rc = posix_spawn_file_actions_adddup2(&actions, sources[1], 5);
    if (!rc && credential >= 0) rc = posix_spawn_file_actions_adddup2(&actions, sources[2], 6);
    if (!rc) rc = posix_spawn_file_actions_addclosefrom_np(&actions, credential >= 0 ? 7 : config >= 0 ? 6 : 4);
    pid_t pid = -1;
    if (!rc) rc = posix_spawn(&pid, exe, &actions, NULL, (char *const *)argv, (char *const *)envp);
    if (!rc) { *channel = sockets[0]; *child_pid = (int)pid; }
done:
    if (initialized) posix_spawn_file_actions_destroy(&actions);
    if (sockets[1] >= 0) close(sockets[1]);
    for (int i = 0; i < 3; i++) if (sources[i] >= 0) close(sources[i]);
    if (rc && sockets[0] >= 0) close(sockets[0]);
    return rc;
#endif
}
int adfl_worker_spawn(const char *exe, const char *const *argv, const char *const *envp,
                      int config, int mechanisms, int *channel, int *child_pid) {
    return spawn_core(exe, argv, envp, config, mechanisms, -1, channel, child_pid);
}
int adfl_worker_spawn_owned(const char *exe, const char *const *argv, const char *const *envp,
                      int config, int mechanisms, int credential, int *channel, int *child_pid) {
    if (credential < 0) return EINVAL;
    return spawn_core(exe, argv, envp, config, mechanisms, credential, channel, child_pid);
}
int adfl_worker_child_send_identity(int channel) {
    int pidfd = (int)syscall(SYS_pidfd_open, getpid(), 0);
    if (pidfd < 0) return errno;
    unsigned char tag = 0xa1; /* magic A, identity protocol version1 */
    struct iovec vector = {&tag, 1};
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(int))]; } ancillary = {0};
    struct msghdr message = {0};
    message.msg_iov = &vector; message.msg_iovlen = 1;
    message.msg_control = ancillary.bytes; message.msg_controllen = sizeof(ancillary.bytes);
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS; header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &pidfd, sizeof(pidfd));
    ssize_t sent;
    do { sent = sendmsg(channel, &message, MSG_NOSIGNAL); } while (sent < 0 && errno == EINTR);
    int rc = sent == 1 ? 0 : sent < 0 ? errno : EIO;
    close(pidfd); return rc;
}
static int validate_pidfd(int fd, int expected) {
    /* Kernel fdinfo binds the received descriptor to the sender's namespace PID.
     * A reaped/dead/unidentifiable target fails closed; never signal a PID number. */
    char path[64]; snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
    FILE *file = fopen(path, "re");
    if (!file) return errno;
    char *line = NULL; size_t capacity = 0; int actual = -1;
    while (getline(&line, &capacity, file) >= 0)
        if (sscanf(line, "Pid:\t%d", &actual) == 1) break;
    free(line); fclose(file);
    if (actual != expected || expected <= 0) return EPROTO;
    siginfo_t info = {0};
    if (waitid(P_PIDFD, (id_t)fd, &info, WEXITED | WNOHANG | WNOWAIT)) return errno;
    if (info.si_pid && info.si_pid != expected) return EPROTO;
    return 0;
}
int adfl_worker_parent_receive_identity(int channel, int expected, int *out) {
    if (!out || expected <= 0) return EINVAL;
    *out = -1;
    unsigned char tag = 0;
    struct iovec vector = {&tag, 1};
    union { struct cmsghdr align; unsigned char bytes[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(8 * sizeof(int))]; } ancillary = {0};
    struct msghdr message = {0}; message.msg_iov = &vector; message.msg_iovlen = 1;
    message.msg_control = ancillary.bytes; message.msg_controllen = sizeof(ancillary.bytes);
    ssize_t received = recvmsg(channel, &message, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    if (received < 0) return errno;
    int fds[8], count = 0, credentials = 0, sender = -1, malformed = 0;
    for (struct cmsghdr *h = CMSG_FIRSTHDR(&message); h; h = CMSG_NXTHDR(&message, h)) {
        if (h->cmsg_level != SOL_SOCKET || h->cmsg_len < CMSG_LEN(0)) { malformed = 1; continue; }
        size_t bytes = h->cmsg_len - CMSG_LEN(0);
        if (h->cmsg_type == SCM_RIGHTS) {
            if (bytes % sizeof(int)) malformed = 1;
            for (size_t i = 0; i < bytes / sizeof(int); i++) {
                int fd; memcpy(&fd, CMSG_DATA(h) + i * sizeof(int), sizeof(fd));
                if (count < 8) fds[count++] = fd; else { close(fd); malformed = 1; }
            }
        } else if (h->cmsg_type == SCM_CREDENTIALS && bytes == sizeof(struct ucred)) {
            struct ucred cred; memcpy(&cred, CMSG_DATA(h), sizeof(cred)); sender = cred.pid; credentials++;
        } else malformed = 1;
    }
    int rc = 0;
    if (received != 1 || tag != 0xa1 || message.msg_flags & (MSG_CTRUNC | MSG_TRUNC) ||
        malformed || count != 1 || credentials != 1 || sender != expected) rc = EPROTO;
    if (!rc) rc = validate_pidfd(fds[0], expected);
    if (!rc) {
        int disabled = 0;
        if (setsockopt(channel, SOL_SOCKET, SO_PASSCRED, &disabled, sizeof(disabled))) rc = errno;
    }
    if (!rc) { *out = fds[0]; return 0; }
    for (int i = 0; i < count; i++) close(fds[i]);
    return rc;
}
int adfl_worker_signal_kill(int pidfd) {
    return syscall(SYS_pidfd_send_signal, pidfd, SIGKILL, NULL, 0) == 0 ? 0 : errno;
}
int adfl_worker_reap_nonblocking_status(int pidfd, int *outcome) {
    if (!outcome) return EINVAL;
    *outcome = 0;
    siginfo_t info = {0};
    if (waitid(P_PIDFD, (id_t)pidfd, &info, WEXITED | WNOHANG)) {
        int status = errno;
        if (status != ECHILD) return status;
        /* Another reaper may have consumed the exit. ECHILD alone does not
         * establish termination; require the retained pidfd to signal exit. */
        struct pollfd descriptor = { .fd = pidfd, .events = POLLIN };
        int ready = poll(&descriptor, 1, 0);
        if (ready < 0) return errno;
        return ready && (descriptor.revents & POLLIN) ? 0 : ECHILD;
    }
    if (!info.si_pid) return EAGAIN;
    if ((info.si_code == CLD_EXITED || info.si_code == CLD_KILLED || info.si_code == CLD_DUMPED) &&
        info.si_status >= 0 && info.si_status <= 255)
        *outcome = info.si_code * 256 + info.si_status;
    return 0;
}
int adfl_worker_reap_nonblocking(int pidfd) {
    int outcome;
    return adfl_worker_reap_nonblocking_status(pidfd, &outcome);
}
