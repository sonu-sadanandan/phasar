#include <stdio.h>
#include <string.h>
const char *source(void);
void sink(const char *);
const char *sanitize(const char *s) {
  static char safe[64];
  // trivial sanitizer: copy only digits (toy example)
  size_t j = 0;
  for (size_t i = 0; s[i] && j < sizeof(safe)-1; ++i)
    if (s[i] >= '0' && s[i] <= '9') safe[j++] = s[i];
  safe[j] = 0;
  return safe;
}
const char *source(void) {
  static char buf[64];
  fgets(buf, sizeof(buf), stdin);
  return buf;
}
void sink(const char *p);
int main() {
  const char *x = source();
  const char *y = sanitize(x);
  sink(y); // should NOT report (sanitized)
}
void sink(const char *p) { (void)p; }
