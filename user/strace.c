#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
  if (argc < 2) {
    fprintf(2, "Usage: strace command [args...]\n");
    exit(1);
  }

  int pid = fork();
  if (pid < 0) {
    fprintf(2, "fork failed\n");
    exit(1);
  }

  if (pid == 0) {
    exec(argv[1], argv + 1);
    fprintf(2, "exec failed\n");
    exit(1);
  } else {
    trace(pid);
    wait(0);
  }

  exit(0);
}
