#include "../fs/operations.h"
#include <assert.h>
#include <string.h>
#include <pthread.h>

#define COUNT 5
#define SIZE 300
#define THREADS 5

/*
    This test creates one file, and then threads open the
    system and write SIZE (each one), and then close it
    after joining the threads then it verifies if the writen is 
    the sum of all the writes, (if SIZE*THREADS == I_SIZE)
*/


void* routine() {

    char* path = "/f1";
    char input[SIZE]; 
    memset(input, 'A', SIZE);

    // open the tfs and create the file
    int fd = tfs_open(path, TFS_O_APPEND);
    assert(fd != -1);

    for (int i = 0; i < COUNT; i++) {
        assert(tfs_write(fd, input, SIZE) == SIZE);
    }

    assert(tfs_close(fd) != -1);
    // write 256 in the inode (each thread)

    pthread_exit(0);
}


int main() {

    pthread_t th[THREADS];

    char* path = "/f1";

    char input[SIZE]; 
    memset(input, 'A', SIZE);

    char output [SIZE];

    assert(tfs_init() != -1);

    // open the tfs and create 1 inode
    int fd = tfs_open(path, TFS_O_CREAT);
    assert(fd != -1);

    // close the tfs, with 1 inode created
    assert(tfs_close(fd) != -1);

    // Create the threads
    for (int i = 0; i < THREADS; i++) {
        if (pthread_create(&th[i], NULL, &routine, NULL) != 0) {
            perror("Error: Create threads");
        }
    }

    // join the threads
    for (int i = 0; i < THREADS; i++) {
        if (pthread_join(th[i], NULL) != 0) {
            perror("Error: Join threads");
        }
    }

    fd = tfs_open(path, 0);
    assert(fd != -1 );

    for (int i = 0; i < COUNT; i++) {
        assert(tfs_read(fd, output, SIZE) == SIZE);
        assert (memcmp(input, output, SIZE) == 0);
    }

    assert(tfs_close(fd) != -1);

    printf("Sucessful test\n");

    return 0;
}
