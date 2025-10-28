#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int main(void) {
  int pid = getpid();
  trace(pid);

  exec("grep", 0);
  open("README", 0);
  read(3, 0, 1023);
  close(3);
  exit(0);
}
