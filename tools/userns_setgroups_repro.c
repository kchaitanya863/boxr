#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/wait.h>
#include <errno.h>

static int writef(const char *p, const char *v) {
  int fd = open(p, O_WRONLY);
  if (fd < 0) return -1;
  int n = write(fd, v, strlen(v));
  close(fd);
  return n < 0 ? -1 : 0;
}

static void readf(const char *p, char *buf, size_t n) {
  int fd = open(p, O_RDONLY);
  if (fd < 0) {
    snprintf(buf, n, "open_err");
    return;
  }
  ssize_t r = read(fd, buf, n - 1);
  close(fd);
  if (r < 0) {
    snprintf(buf, n, "read_err");
    return;
  }
  buf[r] = 0;
}

static int child(void *arg) {
  int wfd = *(int *)arg;
  writef("/proc/self/setgroups", "deny");
  char msg[32];
  snprintf(msg, sizeof(msg), "%d\n", getpid());
  write(wfd, msg, strlen(msg));
  char c;
  read(0, &c, 1);
  char sg[32];
  readf("/proc/self/setgroups", sg, sizeof(sg));
  fprintf(stderr, "child setgroups=%s\n", sg);
  if (writef("/proc/self/setgroups", "allow") == 0) {
    readf("/proc/self/setgroups", sg, sizeof(sg));
    fprintf(stderr, "child after self allow=%s\n", sg);
  } else {
    fprintf(stderr, "child self allow write failed errno=%d\n", errno);
  }
  return 0;
}

int main(int argc, char **argv) {
  int use_new = argc > 1 && strcmp(argv[1], "newidmap") == 0;
  char stack[1024 * 1024];
  int p[2];
  if (pipe(p) < 0) return 1;
  int wfd = p[1];
  pid_t pid = clone(child, stack + sizeof(stack), CLONE_NEWUSER | SIGCHLD, &wfd);
  if (pid < 0) {
    perror("clone");
    return 1;
  }
  close(p[1]);
  char buf[32] = {0};
  read(p[0], buf, sizeof(buf) - 1);
  int cpid = atoi(buf);
  fprintf(stderr, "mapped child pid=%d\n", cpid);
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/setgroups", cpid);
  writef(path, "deny");
  if (use_new) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "newuidmap %d 0 100000 65536", cpid);
    int rc1 = system(cmd);
    snprintf(cmd, sizeof(cmd), "newgidmap %d 0 100000 65536", cpid);
    int rc2 = system(cmd);
    fprintf(stderr, "newuidmap/newgidmap system rc=%d %d\n", rc1, rc2);
  } else {
    snprintf(path, sizeof(path), "/proc/%d/uid_map", cpid);
    writef(path, "0 100000 65536\n");
    snprintf(path, sizeof(path), "/proc/%d/gid_map", cpid);
    writef(path, "0 100000 65536\n");
  }
  char sg[32];
  snprintf(path, sizeof(path), "/proc/%d/setgroups", cpid);
  readf(path, sg, sizeof(sg));
  fprintf(stderr, "parent after map setgroups=%s\n", sg);
  writef(path, "allow");
  readf(path, sg, sizeof(sg));
  fprintf(stderr, "parent after allow write=%s\n", sg);
  write(p[0], "x", 1);
  close(p[0]);
  waitpid(pid, NULL, 0);
  return 0;
}
