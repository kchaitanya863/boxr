/* Minimal mount_setattr idmap probe (linked by check_podman_bats_prereqs.sh). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif

#ifndef MS_PRIVATE
#define MS_PRIVATE (1 << 18)
#endif
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif
#ifndef AT_RECURSIVE
#define AT_RECURSIVE 0x8000
#endif
#ifndef SYS_open_tree
#define SYS_open_tree 428
#endif
#ifndef SYS_mount_setattr
#define SYS_mount_setattr 442
#endif

#ifndef SYS_mount_setattr
#define SYS_mount_setattr 442
#endif

#ifndef MOUNT_ATTR_IDMAP
#define MOUNT_ATTR_IDMAP 0x00100000
#endif

static int child(void *arg) {
  (void)arg;
  char m[64];
  snprintf(m, sizeof m, "0 100000 65536\n");
  write(open("/proc/self/uid_map", O_WRONLY), m, strlen(m));
  write(open("/proc/self/gid_map", O_WRONLY), m, strlen(m));
  pause();
  return 0;
}

int main(void) {
  char stack[1024 * 1024];
  int pid = clone(child, stack + sizeof stack, CLONE_NEWUSER | SIGCHLD, NULL);
  if (pid < 0) {
    perror("clone");
    return 1;
  }
  char path[64];
  snprintf(path, sizeof path, "/proc/%d/ns/user", pid);
  int userns = open(path, O_RDONLY);
  if (userns < 0) {
    printf("idmap probe: open userns: %s\n", strerror(errno));
    kill(pid, SIGKILL);
    return 0;
  }
  const char *tmpdir = "/tmp";
  int tree = syscall(SYS_open_tree, AT_FDCWD, tmpdir, 1 /* OPEN_TREE_CLONE */);
  if (tree < 0) {
    printf("idmap probe: open_tree: %s (160 keep-id may be red)\n", strerror(errno));
    close(userns);
    kill(pid, SIGKILL);
    return 0;
  }
  struct mount_attr attr = {0};
  attr.attr_set = MOUNT_ATTR_IDMAP;
  attr.userns_fd = (unsigned long)userns;
  attr.propagation = MS_PRIVATE;
  int rc = syscall(SYS_mount_setattr, tree, "", AT_EMPTY_PATH | AT_RECURSIVE, &attr, sizeof attr);
  if (rc == 0) {
    printf("idmap probe: mount_setattr ok (160 keep-id prerequisite likely met)\n");
  } else {
    printf("idmap probe: mount_setattr: %s (160 keep-id likely red)\n", strerror(errno));
  }
  close(tree);
  close(userns);
  kill(pid, SIGKILL);
  waitpid(pid, NULL, 0);
  return 0;
}
