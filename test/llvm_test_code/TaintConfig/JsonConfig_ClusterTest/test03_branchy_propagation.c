#include <stdio.h>
const char *source(void);
void sink(const char *);
int coin(void) { return 1; } // pretend unknown
int main() {
  const char *a = "CONST";
  const char *b = source();   // tainted
  const char *x;
  if (coin()) x = a; else x = b;
  sink(x); // report due to feasible tainted path
}
const char *source(void) {
  static char buf[16];
  fgets(buf, sizeof(buf), stdin);
  return buf;
}
void sink(const char *p) { (void)p; }
