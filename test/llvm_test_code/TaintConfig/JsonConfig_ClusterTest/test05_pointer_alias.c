#include <stdio.h>
void sink(const char *);
int main() {
  char buf[32];
  fgets(buf, sizeof(buf), stdin); // taint buf’s contents
  char *p = buf;
  char *q = p;
  sink(q); // report
}
void sink(const char *p) { (void)p; }
