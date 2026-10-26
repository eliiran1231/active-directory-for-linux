#define _GNU_SOURCE
#include "adfl_worker.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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
    int rc;
    while ((rc = adfl_worker_reap_nonblocking(pidfd)) == EAGAIN || rc == EINTR) {
        assert(milliseconds() < until);
        struct pollfd p = {pidfd, POLLIN, 0}; (void)poll(&p, 1, 20);
    }
    assert(rc == 0);
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
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--child")) {
        /* No unrelated descriptors or inherited environment survive exec. */
        assert(getenv("ADFL_WORKER_FIXTURE") && !strcmp(getenv("ADFL_WORKER_FIXTURE"), "isolated"));
        assert(fcntl(3, F_GETFD) >= 0);
        for (int fd = 4; fd < 128; fd++) assert(fcntl(fd, F_GETFD) < 0 && errno == EBADF);
        assert(!adfl_worker_child_send_identity(3));
        const char ready[] = "READY"; assert(write(3, ready, sizeof(ready)) == sizeof(ready));
        for (;;) pause(); /* real blocked child; parent must kill via received pidfd */
    }
    assert(adfl_worker_abi_version() == 1);
    int self = (int)syscall(SYS_pidfd_open, getpid(), 0); assert(self >= 0);
    assert(adfl_worker_reap_nonblocking(self) == ECHILD); /* live non-child is not exit */
    close(self);
    char executable[4096]; ssize_t length = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
    assert(length > 0 && (size_t)length < sizeof(executable) - 1); executable[length] = 0;
    const char *args[] = {executable, "--child", NULL};
    const char *environment[] = {"ADFL_WORKER_FIXTURE=isolated", NULL};
    int channel = -1, child = -1;
    assert(adfl_worker_spawn("relative", args, environment, &channel, &child) == EINVAL);
    assert(channel == -1 && child == -1);
    int before_failure = fd_count();
    assert(adfl_worker_spawn("/definitely-missing-adfl-worker", args, environment, &channel, &child) == ENOENT);
    assert(channel == -1 && child == -1 && fd_count() == before_failure);
    /* An unrelated non-CLOEXEC fd must not escape even if it occupies fd3. */
    int unrelated = open("/dev/null", O_RDONLY); assert(unrelated >= 0);
    assert(!adfl_worker_spawn(executable, args, environment, &channel, &child));
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
    puts("PASS: real exec isolation, kernel pidfd identity, blocked-child kill/reap and malformed handoff cleanup; no LDAP or credentials.");
    return 0;
}
