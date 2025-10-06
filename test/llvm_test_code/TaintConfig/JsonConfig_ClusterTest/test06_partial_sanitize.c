#include <stdio.h>
const char *source(void);
const char *sanitize(const char *);
void sink(const char *);
int coin(void);

int main() {
  const char *d = source();
  const char *e;
  if (coin()) e = sanitize(d);
  else e = d;           // unsanitized path
  sink(e);              // report due to else-branch
}
int coin(void) { return 1; }
const char *source(void) {
  static char buf[64];
  fgets(buf, sizeof(buf), stdin);
  return buf;
}
const char *sanitize(const char *s) { return "CLEAN"; }
void sink(const char *p) { (void)p; }
