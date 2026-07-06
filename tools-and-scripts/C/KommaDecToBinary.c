#include <stdio.h>

int main() {
    int R;
    float decimal;

    printf("Als 0.x eigeben: ");
    scanf("%f", &decimal);
    do{
        decimal *= 2;
        if (decimal >= 1.0){
            decimal -=1;
            R = 1;
        }
        else { R = 0;}
        printf("%.5f R: %d\n", decimal, R);
    }while (decimal != 0.0);
    return 0;
}
