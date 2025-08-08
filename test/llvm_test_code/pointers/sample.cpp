#include <iostream>

int global_x;

void foo(int *p, int *q) {
    *p = *q;
}

int *bar() {
    return &global_x;
}

int main() {
    int a = 10, b = 20, c = 30;
    foo(&a, &b);
    foo(&c, &b);

    int *ptr = bar();
    *ptr = 42;

    return 0;
}
