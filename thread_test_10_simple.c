#include "../fs/operations.h"
#include <assert.h>
#include <string.h>
#include <pthread.h>

#define COUNT 30
#define SIZE 256
#define THREADS 10

/*
   This test fills in a new file up to 8,5 blocks via multiple writes, 
   with 10 threads, each write always targeting only 1 block of the file, 
   then checks if the file contents are as expected
*/


void* routine() {

    char *path = "/f1";

    char input[SIZE]; 
    memset(input, 'A', SIZE);
    char output [SIZE];

    // open the tfs
    int fd = tfs_open(path, TFS_O_CREAT);
    assert(fd != -1);

    for (int i = 0; i < COUNT; i++) {
        printf("%d\n",i);
        assert(tfs_write(fd, input, SIZE) == SIZE);
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
    pthread_exit(0);
} 



int main() {

    pthread_t th[THREADS];
    int i;

    assert(tfs_init() != -1);


    for (i = 0; i < THREADS; i++) {
        if (pthread_create(&th[i], NULL, &routine, NULL) != 0) {
            perror("Error: Create threads");
        }
    }

    for (i = 0; i < THREADS; i++) {
        if (pthread_join(th[i], NULL) != 0) {
            perror("Error: Join threads");
        }
    }

    printf("Sucessful test\n");

    return 0;
}
