#include <stdio.h>
#include <stdlib.h>

// TODO: structs, global variables, etc.
struct listelement {
	int value;
	struct listelement *next;
};

typedef struct listelement listelement;
static listelement *first = NULL; //Kopf 
static listelement *last = NULL;

static int insertElement(int value){
	if(value<0) { 
		return -1;
	}
	for (listelement *i = first; i != NULL; i = i->next){
		if(value == i->value){
			return -1;
		}
	}
	if (first == NULL){
		listelement *newElement;
		newElement = malloc(sizeof(listelement));
		if (newElement == NULL){
			return -1;
		}
		newElement->next = NULL;
		newElement->value = value;
		first = newElement;
		last = newElement;
		return value;
	}
	else{
		listelement *newElement;
		newElement = malloc(sizeof(listelement));
		if (newElement == NULL){
			return -1;
		}
		last->next = newElement;
		newElement->value = value;
		last = newElement;
		newElement->next = NULL;
		return value;
	}
}

static int removeElement(){
    if (first == NULL){
        return -1;
    } else {
        listelement *a = first;
		int b = first->value;
		first = first->next;
		if (first == NULL) {
    		last = NULL;
		}
		free(a);
		return b;
    }
}


int main (int argc, char* argv[]) {
	printf("insert 47: %d\n", insertElement(47));
	printf("insert 11: %d\n", insertElement(11));
	printf("insert 23: %d\n", insertElement(23));
	printf("insert 11: %d\n", insertElement(11));

	// TODO: add more tests
	printf("remove: %d\n", removeElement());
	printf("remove: %d\n", removeElement());

	// TODO: add more tests
	printf("remove: %d\n", removeElement());
	printf("remove: %d\n", removeElement());
	printf("insert -11: %d\n", insertElement(-11));
	printf("insert 0: %d\n", insertElement(0));
	printf("remove: %d\n", removeElement());
	printf("remove: %d\n", removeElement());
	printf("insert 47: %d\n", insertElement(47));
	printf("remove: %d\n", removeElement());
	printf("insert 46: %d\n", insertElement(46));
	printf("insert 47: %d\n", insertElement(47));
	printf("remove: %d\n", removeElement());
	printf("insert 47: %d\n", insertElement(47));
	exit(EXIT_SUCCESS);
}
