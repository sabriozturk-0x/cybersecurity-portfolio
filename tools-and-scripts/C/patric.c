#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include "triangle.h"
#include "sem.h"

sem_t sem;
int total_boundary = 0;
int total_interior = 0;
int active_threads = 0;
int done_threads = 0;

void *Output(void *arg) {
    while (true) {
        printf("\rBoundary: %d, Interior: %d, Active: %d, Done: %d.", total_boundary, total_interior, active_threads, done_threads);
        fflush(stdout);
        sleep(1); // Output per secound
    }
    return NULL;
}

void Callback(int boundary, int interior) {
    total_boundary += boundary;
    total_interior += interior;
}

void *CountPoints(void *trian) {
    sem_dec(&sem);
    struct triangle *tri_send = (struct triangle*)trian;
    active_threads++;
    countPoints(*tri_send, Callback);
    sem_inc(&sem);
    active_threads--;
    done_threads++;
    free(tri_send);
    return NULL;
}

int main(int argc, char *argv[]) {
    int max_threads = atoi(argv[1]);
    sem_init(&sem, max_threads); // max active threads

    pthread_t output_thread_id;
    pthread_create(&output_thread_id, NULL, Output, NULL);
    pthread_detach(output_thread_id);

    char s[64];        
    while (fgets(s, sizeof(s), stdin) != NULL) { //read lines
        int x1, y1, x2, y2, x3, y3;
        struct triangle *tri = malloc(sizeof(struct triangle));
        if (sscanf(s, "(%d,%d),(%d,%d),(%d,%d)", &x1, &y1, &x2, &y2, &x3, &y3) != 6) {
            perror("input failed");
            free(tri);
            continue; // to next line
        }
        tri->point[0].x = x1; tri->point[0].y = y1;
        tri->point[1].x = x2; tri->point[1].y = y2;
        tri->point[2].x = x3; tri->point[2].y = y3;
        //sem_dec(&sem);
        //for (int i = 0; i < max_threads; i++) {
            pthread_t thread_id;
            if (pthread_create(&thread_id, NULL, CountPoints, tri) != 0) {
                perror("thread failed");
                exit(EXIT_FAILURE);
            }
        pthread_detach(thread_id); //join()
    }
    return 0;
}


