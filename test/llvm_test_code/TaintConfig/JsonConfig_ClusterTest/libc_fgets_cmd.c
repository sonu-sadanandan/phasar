// libc_fgets_cmd.c — mirrors Juliet CWE-78 shape
// Expected: report sink hit ONLY IF your cluster taints the memory of arg0 for fgets.

#include <stdio.h>
#include <stdlib.h>

int system_sink(const char *cmd) {  // alias name if you prefer to keep "system" pure
  return system(cmd);
}

int main(void) {
  char buf[100] = "ls ";            // prefill like Juliet does
  size_t len = 3;                   // strlen("ls ")
  if (sizeof(buf) - len > 1) {
    if (fgets(buf + len, sizeof(buf) - (int)len, stdin)) {
      size_t newlen = 0;
      for (; buf[newlen] != 0; ++newlen) ;
      if (newlen && buf[newlen - 1] == '\n') buf[newlen - 1] = 0;
    }
  }
  return system_sink(buf);          // <— tainted if fgets taints arg0 memory
}
