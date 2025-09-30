#include <cstdio>

// Mangled: _Z6sourcev
const char* source() {
  static char buf[128];
  if (!std::fgets(buf, sizeof buf, stdin)) {
    buf[0] = '\0';
  }
  return buf; 
}

// Mangled: _Z4sinkPKc
void sink(const char* s) {
  std::printf("SINK: '%s'\n", s ? s : "(null)");
}

int main(int argc, char**) {
  const char* x   = "inputData"; 
  const char* y   = source();    

  const char* ptr1 = x;
  const char* ptr2 = y;
  const char* ptr3 = nullptr;

  if (argc > 1) {
    ptr3 = ptr1; 
  } else {
    ptr3 = ptr2; 
  }

  sink(ptr1);
  sink(ptr3);

  return 0;
}
