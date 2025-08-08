#include <iostream>

int global_x = 10;
int global_y = 20;

void modify(int *a, int *b) {
    *a = *b + 1;
}

void pass_alias(int *p) {
    modify(p, p);
}

int main() {
    int x = 5;
    int y = 6;
    int *p1 = &x;
    int *p2 = &y;
    int *p3 = &x;

    modify(p1, p2);   // no alias between p1 and p2
    modify(p1, p3);   // p1 and p3 alias
    pass_alias(p1);   // p1 aliases with itself

    return 0;
}
