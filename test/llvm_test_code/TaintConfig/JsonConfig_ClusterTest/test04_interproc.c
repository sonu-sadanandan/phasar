#include <stdio.h>
const char *source(void);
void sink(const char *);
static const char *id(const char *p) { return p; }
int main() {
  const char *t = source();
  const char *u = id(t);
  sink(u); // report
}
const char *source(void) {
  static char buf[32];
  fgets(buf, sizeof(buf), stdin);
  return buf;
}
void sink(const char *p) { (void)p; }
