#include <stdio.h>
void sink(const char *);
int main() {
  char *x;
  char buf[32];
  fgets(buf, sizeof(buf), stdin); // tainted
  x = buf;        // tainted
  x = "SAFE";     // overwrite with safe constant
  sink(x);        // should NOT report
}
void sink(const char *p) { (void)p; }
