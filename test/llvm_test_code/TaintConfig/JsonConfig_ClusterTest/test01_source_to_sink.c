#include <stdio.h>
#include <string.h>

const char *source(void) {
  static char buf[64];
  fgets(buf, sizeof(buf), stdin); // untrusted
  return buf;
}
void sink(const char *p) { printf("%s\n", p); } // model as sink

int main() {
  const char *x = source();
  sink(x); // should report
}
