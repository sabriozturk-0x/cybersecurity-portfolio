#include <stdio.h>
#include <string.h>
void selectionsort(int *a, int index) {
   int min_index, t;
   for(int i = 0; i < index; i++) {
      min_index = i;
      for (int y = i+1; y < index; y++){
         if(a[y] < a[min_index]){
            min_index = y;
         }
      }
      if(min_index != i){
         t = a[i];
         a[i] = a[min_index];
         a[min_index] = t;
      }
         
   }
}


int main(){
   int numbers[] = {8,6,3,4,5,7,2,1,9,0};
   selectionsort(numbers, 10);
   for(int i = 0; i < 10; i++){
      printf("%d ", numbers[i]);
   }   
}