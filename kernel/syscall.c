#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "syscall.h"
#include "defs.h"


// Fetch the uint64 at addr from the current process.
int
fetchaddr(uint64 addr, uint64 *ip)
{
  struct proc *p = myproc();
  if(addr >= p->sz || addr+sizeof(uint64) > p->sz) // both tests needed, in case of overflow
    return -1;
  if(copyin(p->pagetable, (char *)ip, addr, sizeof(*ip)) != 0)
    return -1;
  return 0;
}

// Fetch the nul-terminated string at addr from the current process.
// Returns length of string, not including nul, or -1 for error.
int
fetchstr(uint64 addr, char *buf, int max)
{
  struct proc *p = myproc();
  if(copyinstr(p->pagetable, buf, addr, max) < 0)
    return -1;
  return strlen(buf);
}

static uint64
argraw(int n)
{
  struct proc *p = myproc();
  switch (n) {
  case 0:
    return p->trapframe->a0;
  case 1:
    return p->trapframe->a1;
  case 2:
    return p->trapframe->a2;
  case 3:
    return p->trapframe->a3;
  case 4:
    return p->trapframe->a4;
  case 5:
    return p->trapframe->a5;
  }
  panic("argraw");
  return -1;
}

// Fetch the nth 32-bit system call argument.
void
argint(int n, int *ip)
{
  *ip = argraw(n);
}

// Retrieve an argument as a pointer.
// Doesn't check for legality, since
// copyin/copyout will do that.
void
argaddr(int n, uint64 *ip)
{
  *ip = argraw(n);
}

// Fetch the nth word-sized system call argument as a null-terminated string.
// Copies into buf, at most max.
// Returns string length if OK (including nul), -1 if error.
int
argstr(int n, char *buf, int max)
{
  uint64 addr;
  argaddr(n, &addr);
  return fetchstr(addr, buf, max);
}

// Prototypes for the functions that handle system calls.
extern uint64 sys_fork(void);
extern uint64 sys_exit(void);
extern uint64 sys_wait(void);
extern uint64 sys_pipe(void);
extern uint64 sys_read(void);
extern uint64 sys_kill(void);
extern uint64 sys_exec(void);
extern uint64 sys_fstat(void);
extern uint64 sys_chdir(void);
extern uint64 sys_dup(void);
extern uint64 sys_getpid(void);
extern uint64 sys_sbrk(void);
extern uint64 sys_sleep(void);
extern uint64 sys_uptime(void);
extern uint64 sys_open(void);
extern uint64 sys_write(void);
extern uint64 sys_mknod(void);
extern uint64 sys_unlink(void);
extern uint64 sys_link(void);
extern uint64 sys_mkdir(void);
extern uint64 sys_close(void);
extern uint64 sys_trace(void); // flag!

// An array mapping syscall numbers from syscall.h
// to the function that handles the system call.
static uint64 (*syscalls[])(void) = {
[SYS_fork]    sys_fork,
[SYS_exit]    sys_exit,
[SYS_wait]    sys_wait,
[SYS_pipe]    sys_pipe,
[SYS_read]    sys_read,
[SYS_kill]    sys_kill,
[SYS_exec]    sys_exec,
[SYS_fstat]   sys_fstat,
[SYS_chdir]   sys_chdir,
[SYS_dup]     sys_dup,
[SYS_getpid]  sys_getpid,
[SYS_sbrk]    sys_sbrk,
[SYS_sleep]   sys_sleep,
[SYS_uptime]  sys_uptime,
[SYS_open]    sys_open,
[SYS_write]   sys_write,
[SYS_mknod]   sys_mknod,
[SYS_unlink]  sys_unlink,
[SYS_link]    sys_link,
[SYS_mkdir]   sys_mkdir,
[SYS_close]   sys_close,
[SYS_trace]   sys_trace, // flag!
};

// flag!
// Map syscall numbers to names for tracing, it is convenient for us to print it out after tracing.
static char *syscall_names[] = {
  [SYS_fork]   = "fork",
  [SYS_exit]   = "exit",
  [SYS_wait]   = "wait",
  [SYS_pipe]   = "pipe",
  [SYS_read]   = "read",
  [SYS_kill]   = "kill",
  [SYS_exec]   = "exec",
  [SYS_fstat]  = "fstat",
  [SYS_chdir]  = "chdir",
  [SYS_dup]    = "dup",
  [SYS_getpid] = "getpid",
  [SYS_sbrk]   = "sbrk",
  [SYS_sleep]  = "sleep",
  [SYS_uptime] = "uptime",
  [SYS_open]   = "open",
  [SYS_write]  = "write",
  [SYS_mknod]  = "mknod",
  [SYS_unlink] = "unlink",
  [SYS_link]   = "link",
  [SYS_mkdir]  = "mkdir",
  [SYS_close]  = "close",
  [SYS_trace]  = "trace",
};




// void
// syscall(void)
// {
//   int num;
//   struct proc *p = myproc();

//   num = p->trapframe->a7;
//   if(num > 0 && num < NELEM(syscalls) && syscalls[num]) {
//     // Use num to lookup the system call function for num, call it,
//     // and store its return value in p->trapframe->a0
//     p->trapframe->a0 = syscalls[num]();
//   } else {
//     printf("%d %s: unknown sys call %d\n",
//             p->pid, p->name, num);
//     p->trapframe->a0 = -1;
//   }
// }

// flag!
// 小工具：把 user 空字串安全搬到 kernel buffer
//20/21
// void
// syscall(void)
// {
//   struct proc *p = myproc();
//   int num = p->trapframe->a7;

//   if (num > 0 && num < NELEM(syscalls) && syscalls[num]) {
//     uint64 a0 = argraw(0);
//     uint64 a1 = argraw(1);
//     (void)a1;

//     p->trapframe->a0 = syscalls[num]();
//     uint64 ret = p->trapframe->a0;

//       if (p->traced && num != SYS_write && num != SYS_trace) {
//     char *name = syscall_names[num] ? syscall_names[num] : "unknown";

//     if (num == SYS_open || num == SYS_unlink ||
//         num == SYS_chdir || num == SYS_mkdir || num == SYS_link) {
//       char path[128];
//       if (fetchstr(a0, path, sizeof(path)) < 0)
//         printf("[pid %d] %s(<bad ptr>) = %ld\n", p->pid, name, ret);
//       else
//         printf("[pid %d] %s(\"%s\") = %ld\n", p->pid, name, path, ret);

//     } else if (num == SYS_exec) {
//       char path[128];
//       uint64 argv0;
//       uint64 a1 = argraw(1);
//       if (fetchaddr(a1, &argv0) < 0 || fetchstr(argv0, path, sizeof(path)) < 0)
//         printf("[pid %d] %s(<bad ptr>) = %ld\n", p->pid, name, ret);
//       else
//         printf("[pid %d] %s(\"%s\") = %ld\n", p->pid, name, path, ret);

//     } else {
//       printf("[pid %d] %s(%d) = %ld\n", p->pid, name, (int)a0, ret);
//     }
//   }


//   } else {
//     printf("%d %s: unknown sys call %d\n", p->pid, p->name, num);
//     p->trapframe->a0 = -1;
//   }
// }

void
syscall(void)
{
  struct proc *p = myproc(); // the process now
  int num = p->trapframe->a7; // put the syscall id, which is definded in syscall.h

  if (num > 0 && num < NELEM(syscalls) && syscalls[num]) {
    uint64 a0 = argraw(0); // 取得syscall的第一個參數

    p->trapframe->a0 = syscalls[num](); // 執行對應的syscall
    uint64 ret = p->trapframe->a0; // 把回傳值存下來

    if (p->traced && num != SYS_trace) { // 看看這個pocess有沒有被traced過，然後不要trace自己
      char *name = syscall_names[num] ? syscall_names[num] : "unknown"; // 從上面的syscall_names[]找對應名稱，否則就印unknown

      if (num == SYS_open || num == SYS_unlink ||
          num == SYS_chdir || num == SYS_mkdir || num == SYS_link) { // 這些是檔案類型的syscall，他們的第一個參數是字串(檔案路徑) ex: open("README", O_RDONLY)
        char path[128];
        if (fetchstr(a0, path, sizeof(path)) < 0) // fetchstr(user-space 裡字串的記憶體位址, buffer, 長度)，目的是從userspace複製字串進kernel
          printf("[pid %d] %s(<bad ptr>) = %ld\n", p->pid, name, ret); // 複製失敗，代表這個字串指標無效（例如 user 傳壞掉的指標）
        else
          printf("[pid %d] %s(\"%s\") = %ld\n", p->pid, name, path, ret); // 印出 syscall 名稱 + 檔案路徑 + 回傳值

      } else if (num == SYS_exec) { // exec(char *path, char **argv)，path 是要執行的程式，argv傳遞參數陣列
        char path[128] = {0}; // exec("echo", ["echo", "hello"])，a0 = path = "echo", a1 = argv = pointer to ["echo", "hello"], argv[0] = "echo", argv[1] = "hello"
        uint64 argv0 = 0;
        uint64 a1 = argraw(1);

        int bad = 0;
        if (a1 == 0) {
          bad = 1;
        } else if (fetchaddr(a1, &argv0) < 0) {
          bad = 1;
        } else if (fetchstr(argv0, path, sizeof(path)) < 0) {
          bad = 1;
        }

        if (bad)
          printf("[pid %d] %s(<bad ptr>) = %ld\n", p->pid, name, ret);
        else
          printf("[pid %d] %s(\"%s\") = %ld\n", p->pid, name, path, ret); 
          // 對exec來說，真正的程式名稱不再a0，而是在argv[0]裡面
          // 所以如果直接fetchstr(a0, ...)可能把指標位址當字串讀，然後就會出現亂碼
      } else {
        printf("[pid %d] %s(%d) = %ld\n", p->pid, name, (int)a0, ret); // don't need to fetchstr() ex: read(3, buf, 100)
      }
    }

  } else {
    printf("%d %s: unknown sys call %d\n", p->pid, p->name, num);
    p->trapframe->a0 = -1;
  }
}

//Q1:userspace的輸出和kernel space的trace都會consolewrite()，所以會有交錯。所以要改寫consolewrite()，讓被追蹤的process不要印出任何東西 
//Q2:其他的都是抓第一個參數，而exec要取的是第二個參數(argv)，那才是程式名稱
//Q3:如果不reset，那之後同一個slot的process就也會是traced = 1，這樣可能在沒被要求的情況下被印出來，也有可能因為我們改寫consolewrite導致印不出東西
//Q4:不同的syscall的參數都不一樣，加上第一個通常比較關鍵，所以通常就印第一個






