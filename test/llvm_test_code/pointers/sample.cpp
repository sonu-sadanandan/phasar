#include<iostream>
using namespace std;

int main(){
    int x =1;
    int y =5;

    int *p1 = &x;
    int *p2 = &y;
    int *p4 = &y;

    int *p3;
    if(x>5){
        p3 = p1;
    } else {
        p3 = p2;
    }

return 0;
}
