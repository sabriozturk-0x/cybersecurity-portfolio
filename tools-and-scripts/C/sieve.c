// Vorname:Sabri Nachname:Öztürk Martikelsnummer:108021227680
#include <stdio.h>
#include <stdbool.h>


int main(int argc, char **argv) {
	int i,x,y, MAX = 294;
	//printf("Enter an integer to see, prime numbers under that number: ");
	//scanf("%d", &MAX); 
	bool prime[MAX];

	for(i=2; i<MAX; i++){ //Inistalisiere alles mit true.		
		prime[i] = true;
	}

	for(y=2; y*y<MAX; y++){ // Die Zahlen, die nicht prime sind, werden false
		if (prime[y]){
			for (x = 1 + y; x < MAX+1; x++) {
				if (x % y == 0) {
					prime[x] = false; }
				}
		}
	}
	for(i=2; i<MAX; i++){ //Output		
		if (prime[i] == true){
			printf("%d\n", i);
		}
	}
	return 0;
}
