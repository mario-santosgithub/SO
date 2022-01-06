#include "../fs/operations.h"
#include <assert.h>
#include <string.h>
#include <pthread.h>

#define COUNT 20
#define SIZE 256

pthread_mutex_t mutex;

/**
   This test fills in a new file up to 10 blocks via multiple writes, with 2 threads, 
   each write always targeting only 1 block of the file, 
   then checks if the file contents are as expected
 */


int main() {

    char *path = "/f1";
    pthread_t p1, p2;
    pthread_mutex_init(&mutex, NULL);

    /* Writing this buffer multiple times to a file stored on 1KB blocks will 
       always hit a single block (since 1KB is a multiple of SIZE=256) */
    char input[SIZE]; 
    memset(input, 'A', SIZE);

    char output [SIZE];

    assert(tfs_init() != -1);

    /* Write input COUNT times into a new file */
    int fd = tfs_open(path, TFS_O_CREAT);
    assert(fd != -1);
    for (int i = 0; i < COUNT; i++) {
        assert(tfs_write(fd, input, SIZE) == SIZE);

        /* Supostamente adicionar:
        (isto vai executar as duas threads)
        if (pthread_create(&p1, NULL, &function, NULL) != 0) {
            return 1;
        }
        if (pthread_create(&p2, NULL, &function, NULL) != 0) {
            return 2;
        }

        e dps para juntar os dois processos
        if (pthread_join(p1, NULL) != 0) {
            return 3;
        }
        if (pthread_join(p2, NULL) != 0) {
            return 4;
        }

        isto devia fazer as duas chamadas (uma por thread) no mesmo ciclo,
        o teste deverá passar pois o counter foi reduzido para metade do original
        */
    }
    assert(tfs_close(fd) != -1);

    /* Open again to check if contents are as expected */
    fd = tfs_open(path, 0);
    assert(fd != -1 );

    for (int i = 0; i < COUNT; i++) {
        assert(tfs_read(fd, output, SIZE) == SIZE);
        assert (memcmp(input, output, SIZE) == 0);
    }

    assert(tfs_close(fd) != -1);

    pthread_mutex_destroy(&mutex);
    printf("Sucessful test\n");

    return 0;
}
