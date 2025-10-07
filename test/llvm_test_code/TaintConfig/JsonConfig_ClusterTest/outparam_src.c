// outparam_src.c — out-param taint only, no libc
// Expected: report sink hit ONLY IF your cluster supports tainting memory of arg0.
void source_out(char *dst) {  // OUT param becomes tainted
  dst[0] = 'X'; dst[1] = 0;
}

int sink(const char *p) {     // sink on arg0
  (void)p;
  return 0;
}

int main(void) {
  char buf[16] = {0};
  source_out(buf);            // <— taint into buf (out-param)
  return sink(buf);           // <— should report if out-param is modeled
}
