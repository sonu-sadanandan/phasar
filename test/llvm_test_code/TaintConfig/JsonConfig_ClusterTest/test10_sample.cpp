#include <cstdio>

char* source() {
  static char buf[128];
  // Read tainted data from stdin (user input)
  if (!fgets(buf, sizeof(buf), stdin)) {
    buf[0] = '\0';
  }
  return buf; // <-- return tainted
}

void sink(const char* s) {
  printf("%s\n", s);
}

// Optional sanitizer
const char* sanitize(const char* /*in*/) {
  return "CLEAN";
}

int main() {
  char* a = source();   // tainted
  sink(a);              // should be REPORTED

  const char* b = sanitize(a);
  sink(b);              // should NOT be reported if sanitizer is modeled
  return 0;
}