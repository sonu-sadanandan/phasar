#include <iostream>
#include <string>
std::string source() { std::string s; std::getline(std::cin, s); return s; }
void sink(const std::string &s) { std::cout << s.size() << "\n"; }
int main() {
  auto t = source();
  auto u = t;     // copy
  sink(u);        // report
}
