#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int compare(const void *a, const void *b) { //nicht else/else if verwendet, damit iterativ ist: sonst würde nur erstes char entscheiden
    const char *ia = *(const char **) a;
    const char *ib = *(const char **) b;
    int x = strlen(ia);
    int y = strlen(ib);
    for (int i = 0; i < x || i < y ; i++) {
        if (ia[i] > ib[i]){ 
            return -1;
        }
        if(ia[i] == '\0' && ib[i] == '\0'){ // wenn Strings identisch
            return 0;
        }
        if (ia[i] < ib[i]) {
            return +1;
        }
    }
    if (x > y) { // Wenn ia länger als ib ist
        return -1;
    }
    if (x < y) { // Wenn ib länger als ia ist
        return +1;
    }
    return 0; //sollte nie vorkommen, aber sicher ist sicher :)
}

int main(){
    char c[1024], **Strings = NULL; //String- und Stringshälter
    int i = 0;
    do { 
        if (fgets(c, sizeof(c), stdin) == NULL){ //Wenn keine Zeile (mehr) gibt
            break;
        }
        if (c[0] == '\n') {// Wenn Zeile leer, überspringe auf das nächste Zeile bei stdin
            continue;  
        }
        if (strlen(c) > 100) { // Wenn Zeile länger als 100 char, error hinzufügen und auf das nächste Zeile bei stdin überspringen
            fputs("In dem Zeile gibt es mehr als 100 Zeichen\n", stderr);
            continue;  
        }

        c[strcspn(c, "\n")] = '\0'; //lösche '\n' am Ende
        char *String = malloc(sizeof(char) * (strlen(c)+1)); // Speicher für String + EOF allokieren
        strcpy(String, c); //  c in String kopieren
        Strings = realloc(Strings, (i + 1) * sizeof(char *)); //Stringshälter um neue Elementspeicher erweitern
        Strings[i] = String; // String in Behälter hinzufügen
        i += 1; 
    }while (true);
    qsort(Strings, i, sizeof(char *), compare); // size von char pointer
    //fputs(,stdout);
    for (int y = 0; y < i; y++) {
        fputs(Strings[y], stdout);
        fputs("\n", stdout);
    }
    for (int z = 0; z < i; z++) {
        free(Strings[z]); 
    } 
    free(Strings);
    return 0;
}