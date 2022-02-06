#include "../fs/operations.h"
#include <assert.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#define THREADS 3

/*
    Tfs_copy_to_external_fs with threads
*/


void* routine() {

    char* path = "/f1";
    char *path2 = "external_file1.txt";
    char *path3 = "external_file2.txt";
    char *path4 = "external_file3.txt";


    char *str = "AAA! AAA! AAA! ";
    char to_read1[40];
    char to_read2[40];
    char to_read3[40];



    int file = tfs_open(path, TFS_O_CREAT);
    assert(file != -1);

    assert(tfs_write(file, str, strlen(str)) != -1);

    assert(tfs_close(file) != -1);

    assert(tfs_copy_to_external_fs(path, path2) != -1);
    assert(tfs_copy_to_external_fs(path, path3) != -1);
    assert(tfs_copy_to_external_fs(path,path4) != -1);


    FILE *fp1 = fopen(path2, "r");
    FILE *fp2 = fopen(path3,"r");
    FILE *fp3 = fopen(path4,"r");

    assert(fp1 != NULL);
    assert(fp2 != NULL);

    assert(fread(to_read1, sizeof(char), strlen(str), fp1) == strlen(str));
    assert(fread(to_read2, sizeof(char), strlen(str), fp2) == strlen(str));
    assert(fread(to_read3, sizeof(char), strlen(str), fp3) == strlen(str));

    assert(strcmp(str, to_read1) == 0);
    assert(strcmp(str, to_read2) == 0);
    assert(strcmp(str,to_read3) == 0);


    assert(fclose(fp1) != -1);
    assert(fclose(fp2) != -1);
    assert(fclose(fp3) != -1);

    unlink(path2);
    unlink(path3);
    unlink(path4);

    pthread_exit(0);
}


int main() {

    pthread_t th[THREADS];

    assert(tfs_init() != -1);

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

    printf("Sucessful test\n");

    return 0;
}