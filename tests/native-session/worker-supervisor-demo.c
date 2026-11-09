#define _GNU_SOURCE
#include "adfl_worker.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static long milliseconds(void) {
    struct timespec t; assert(!clock_gettime(CLOCK_MONOTONIC, &t));
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static int wait_identity(int channel, int pid, int *pidfd) {
    long until = milliseconds() + 5000;
    for (;;) {
        int rc = adfl_worker_parent_receive_identity(channel, pid, pidfd);
        if (rc != EAGAIN && rc != EINTR) return rc;
        assert(milliseconds() < until);
        struct pollfd p = {channel, POLLIN, 0}; (void)poll(&p, 1, 20);
    }
}
static void reap(int pidfd) {
    long until = milliseconds() + 5000;
    int rc, outcome = -1;
    while ((rc = adfl_worker_reap_nonblocking_status(pidfd, &outcome)) == EAGAIN || rc == EINTR) {
        assert(milliseconds() < until);
        struct pollfd p = {pidfd, POLLIN, 0}; (void)poll(&p, 1, 20);
    }
    assert(rc == 0);
    assert(outcome == CLD_KILLED * 256 + SIGKILL);
    assert(adfl_worker_reap_nonblocking_status(pidfd, &outcome) == 0 && outcome == 0);
    assert(adfl_worker_reap_nonblocking(pidfd) == 0);
    assert(!adfl_worker_closefd(pidfd));
}
static int fd_count(void) {
    DIR *directory = opendir("/proc/self/fd"); assert(directory);
    int count = 0; while (readdir(directory)) count++;
    closedir(directory); return count;
}
static void malformed_identity(void) {
    for (int scenario = 0; scenario < 6; scenario++) {
        int before = fd_count(), pair[2]; assert(!socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair));
        int yes = 1; assert(!setsockopt(pair[0], SOL_SOCKET, SO_PASSCRED, &yes, sizeof(yes)));
        unsigned char tag = scenario == 0 ? 0xff : 0xa1;
        int source = scenario == 5 ? (int)syscall(SYS_pidfd_open, getpid(), 0) : open("/dev/null", O_RDONLY | O_CLOEXEC); assert(source >= 0);
        int descriptor_count = scenario == 4 ? 16 : scenario == 1 ? 2 : 1;
        struct iovec io = {&tag, 1};
        union { struct cmsghdr align; unsigned char data[CMSG_SPACE(sizeof(int) * 16)]; } ancillary = {0};
        struct msghdr m = {0}; m.msg_iov = &io; m.msg_iovlen = 1;
        m.msg_control = ancillary.data; m.msg_controllen = CMSG_SPACE(sizeof(int) * descriptor_count);
        struct cmsghdr *c = CMSG_FIRSTHDR(&m); c->cmsg_level = SOL_SOCKET; c->cmsg_type = SCM_RIGHTS;
        c->cmsg_len = CMSG_LEN(sizeof(int) * descriptor_count);
        for (int i = 0; i < descriptor_count; i++) memcpy(CMSG_DATA(c) + i * sizeof(source), &source, sizeof(source));
        assert(sendmsg(pair[1], &m, MSG_NOSIGNAL) == 1);
        int received = -1;
        int rc = adfl_worker_parent_receive_identity(pair[0], (int)getpid() + (scenario == 2), &received);
        assert(rc != 0 && received == -1);
        close(source); close(pair[0]); close(pair[1]); assert(fd_count() == before);
    }
}
static void profile_transfer(const char *executable, int owned) {
    int before = fd_count(), config = -1, mechanisms = -1, channel = -1, child = -1;
    const unsigned char bytes[] = "synthetic-profile\n";
    assert(!adfl_worker_profile_create(bytes, sizeof(bytes) - 1, &config));
    assert(!adfl_worker_profile_create(NULL, 0, &mechanisms));
    assert(write(config, "x", 1) < 0 && errno == EPERM);
    assert(ftruncate(config, 0) < 0 && errno == EPERM);
    const char *args[] = {executable, owned ? "--owned-child" : "--profile-child", NULL};
    const char *env[] = {"KRB5_CONFIG=/proc/self/fd/4", "GSS_MECH_CONFIG=/proc/self/fd/5", NULL};
    int held = fd_count();
    assert(adfl_worker_spawn(executable, args, env, config, -1, &channel, &child) == EINVAL);
    assert(adfl_worker_spawn(executable, args, env, mechanisms, mechanisms, &channel, &child) == EINVAL);
    assert(adfl_worker_spawn("/missing-adfl-profile-child", args, env, config, mechanisms, &channel, &child) == ENOENT);
    assert(channel == -1 && child == -1 && fd_count() == held);
    int unsealed = (int)syscall(SYS_memfd_create, "synthetic-unsealed", MFD_CLOEXEC | MFD_ALLOW_SEALING); assert(unsealed >= 0);
    assert(write(unsealed, bytes, sizeof(bytes) - 1) == sizeof(bytes) - 1);
    assert(adfl_worker_spawn(executable, args, env, unsealed, mechanisms, &channel, &child) == EINVAL); close(unsealed);
    /* Deliberately place borrowed sources on the child targets themselves. */
    assert(fcntl(4, F_GETFD) < 0 && fcntl(5, F_GETFD) < 0);
    assert(dup2(config, 4) == 4 && dup2(mechanisms, 5) == 5);
    int credential = -1;
    if (owned) {
        const unsigned char synthetic[] = {0, 1, 2, 3};
        assert(!adfl_worker_credential_create(synthetic, sizeof(synthetic), &credential));
        assert(dup2(credential, 6) == 6);
        assert(adfl_worker_spawn_owned(executable, args, env, 4, 5, -1, &channel, &child) == EINVAL);
        assert(adfl_worker_spawn_owned(executable, args, env, 4, 5, 5, &channel, &child) == EINVAL);
        assert(!adfl_worker_spawn_owned(executable, args, env, 4, 5, 6, &channel, &child));
        close(6); close(credential);
    } else assert(!adfl_worker_spawn(executable, args, env, 4, 5, &channel, &child));
    close(4); close(5); close(config); close(mechanisms);
    int pidfd = -1; assert(!wait_identity(channel, child, &pidfd));
    assert(!adfl_worker_signal_kill(pidfd)); reap(pidfd); close(channel);
    assert(fd_count() == before);
}
int main(int argc, char **argv) {
    if (argc == 2 && (!strcmp(argv[1], "--profile-child") || !strcmp(argv[1], "--owned-child"))) {
        assert(!strcmp(getenv("KRB5_CONFIG"), "/proc/self/fd/4"));
        assert(!strcmp(getenv("GSS_MECH_CONFIG"), "/proc/self/fd/5"));
        char bytes[32] = {0}; assert(pread(4, bytes, sizeof(bytes), 0) == 18);
        assert(!strcmp(bytes, "synthetic-profile\n")); assert(pread(5, bytes, 1, 0) == 0);
        assert(lseek(4, 0, SEEK_CUR) == 0);
        int seals = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
        assert((fcntl(4, F_GET_SEALS) & seals) == seals && (fcntl(5, F_GET_SEALS) & seals) == seals);
        int owned = !strcmp(argv[1], "--owned-child");
        if (owned) {
            unsigned char material[4]; assert(pread(6, material, 4, 0) == 4);
            assert(material[0] == 0 && material[1] == 1 && material[2] == 2 && material[3] == 3);
            assert((fcntl(6, F_GET_SEALS) & seals) == seals);
            assert(write(6, "x", 1) < 0 && errno == EPERM);
        }
        for (int fd = owned ? 7 : 6; fd < 128; fd++) assert(fcntl(fd, F_GETFD) < 0 && errno == EBADF);
        assert(!adfl_worker_child_send_identity(3)); for (;;) pause();
    }
    if (argc == 2 && !strcmp(argv[1], "--child")) {
        /* No unrelated descriptors or inherited environment survive exec. */
        assert(getenv("ADFL_WORKER_FIXTURE") && !strcmp(getenv("ADFL_WORKER_FIXTURE"), "isolated"));
        assert(fcntl(3, F_GETFD) >= 0);
        for (int fd = 4; fd < 128; fd++) assert(fcntl(fd, F_GETFD) < 0 && errno == EBADF);
        assert(!adfl_worker_child_send_identity(3));
        const char ready[] = "READY"; assert(write(3, ready, sizeof(ready)) == sizeof(ready));
        for (;;) pause(); /* real blocked child; parent must kill via received pidfd */
    }
    assert(adfl_worker_abi_version() == 2);
    int self = (int)syscall(SYS_pidfd_open, getpid(), 0); assert(self >= 0);
    assert(adfl_worker_reap_nonblocking(self) == ECHILD); /* live non-child is not exit */
    close(self);
    char executable[4096]; ssize_t length = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
    assert(length > 0 && (size_t)length < sizeof(executable) - 1); executable[length] = 0;
    const char *args[] = {executable, "--child", NULL};
    const char *environment[] = {"ADFL_WORKER_FIXTURE=isolated", NULL};
    int channel = -1, child = -1;
    assert(adfl_worker_spawn("relative", args, environment, -1, -1, &channel, &child) == EINVAL);
    assert(channel == -1 && child == -1);
    int before_failure = fd_count();
    assert(adfl_worker_spawn("/definitely-missing-adfl-worker", args, environment, -1, -1, &channel, &child) == ENOENT);
    assert(channel == -1 && child == -1 && fd_count() == before_failure);
    /* An unrelated non-CLOEXEC fd must not escape even if it occupies fd3. */
    int unrelated = open("/dev/null", O_RDONLY); assert(unrelated >= 0);
    assert(!adfl_worker_spawn(executable, args, environment, -1, -1, &channel, &child));
    assert(fcntl(channel, F_GETFL) & O_NONBLOCK);
    int pidfd = -1; assert(!wait_identity(channel, child, &pidfd));
    assert(fcntl(pidfd, F_GETFD) & FD_CLOEXEC);
    char ready[6]; size_t have = 0; long until = milliseconds() + 5000;
    while (have < sizeof(ready)) {
        ssize_t n = read(channel, ready + have, sizeof(ready) - have);
        if (n > 0) have += (size_t)n;
        else { assert(n < 0 && (errno == EAGAIN || errno == EINTR)); assert(milliseconds() < until); struct pollfd p = {channel, POLLIN, 0}; (void)poll(&p, 1, 20); }
    }
    assert(!strcmp(ready, "READY"));
    assert(adfl_worker_reap_nonblocking(pidfd) == EAGAIN);
    assert(!adfl_worker_signal_kill(pidfd)); reap(pidfd);
    close(channel); close(unrelated);
    malformed_identity();
    profile_transfer(executable, 0);
    profile_transfer(executable, 1);
    puts("PASS: real exec isolation, kernel pidfd identity, blocked-child kill/reap and malformed handoff cleanup; no LDAP or credentials.");
    return 0;
}
