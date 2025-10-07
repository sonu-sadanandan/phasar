// return_src.c — return-taint only
// Expected: report sink hit IF your cluster models tainted return values.

__attribute__((noinline))
char *src(void) {
  static char b[8];
  b[0] = 'X'; b[1] = 0;
  return b;               // <— treat return as tainted
}

__attribute__((noinline))
int sink(const char *p) {  // your engine marks this as a sink on arg0
  (void)p;
  return 0;
}

int main(void) {
  return sink(src());      // <— should report
}
