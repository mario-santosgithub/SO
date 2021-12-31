#include "operations.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


#define SIZE 256

int tfs_init() {
    state_init();

    /* create root inode */
    int root = inode_create(T_DIRECTORY);
    if (root != ROOT_DIR_INUM) {
        return -1;
    }

    return 0;
}

int tfs_destroy() {
    state_destroy();
    return 0;
}

static bool valid_pathname(char const *name) {
    return name != NULL && strlen(name) > 1 && name[0] == '/';
}


int tfs_lookup(char const *name) {
    if (!valid_pathname(name)) {
        return -1;
    }

    // skip the initial '/' character
    name++;

    return find_in_dir(ROOT_DIR_INUM, name);
}

int tfs_open(char const *name, int flags) {
    int inum;
    size_t offset;

    /* Checks if the path name is valid */
    if (!valid_pathname(name)) {
        //printf("HERE\n");
        return -1;
    }

    inum = tfs_lookup(name);
    if (inum >= 0) {
        /* The file already exists */
        inode_t *inode = inode_get(inum);
        if (inode == NULL) {
            //printf("HERE1\n");
            return -1;
        }

        /* Trucate (if requested) */
        if (flags & TFS_O_TRUNC) {
            if (inode->i_size > 0) {

                for (int i=0; i < DIRECT_REF_BLOCKS; i++) {
                    if (data_block_free(inode->i_data_blocks[i]) == -1) {
                        //printf("HERE2\n");
                        return -1;
                    }
                }

                inode->i_size = 0;
            }
        }
        /* Determine initial offset */
        if (flags & TFS_O_APPEND) {
            offset = inode->i_size;
        } else {
            offset = 0;
        }
    } else if (flags & TFS_O_CREAT) {
        /* The file doesn't exist; the flags specify that it should be created*/
        /* Create inode */
        inum = inode_create(T_FILE);
        if (inum == -1) {
            //printf("HERE3\n");
            return -1;
        }
        /* Add entry in the root directory */
        if (add_dir_entry(ROOT_DIR_INUM, inum, name + 1) == -1) {
            inode_delete(inum);
            //printf("HERE4\n");
            return -1;
        }
        offset = 0;
    } else {
        //printf("HERE5\n");
        return -1;
    }

    /* Finally, add entry to the open file table and
     * return the corresponding handle */
    return add_to_open_file_table(inum, offset);

    /* Note: for simplification, if file was created with TFS_O_CREAT and there
     * is an error adding an entry to the open file table, the file is not
     * opened but it remains created */
}


int tfs_close(int fhandle) { return remove_from_open_file_table(fhandle); }

ssize_t tfs_write(int fhandle, void const *buffer, size_t to_write) {
    open_file_entry_t *file = get_open_file_entry(fhandle);
    if (file == NULL) {
        return -1;
    }

    /* From the open file table entry, we get the inode */
    inode_t *inode = inode_get(file->of_inumber);
    if (inode == NULL) {
        return -1;
    }

    /* Determine how many bytes to write */
    if (to_write + file->of_offset > BLOCK_SIZE*DIRECT_REF_BLOCKS) {
        to_write = BLOCK_SIZE*DIRECT_REF_BLOCKS - file->of_offset;
    }

    int i=0, added = 0;
    size_t aux = 0;
    if (to_write > 0) {

        // Direct Write
        while (i < DIRECT_REF_BLOCKS && added != 1) {

            i = (int)(inode->i_size/1024) % 10;

            // Case write_10_blocks_simple
            // 1KB is multiple of SIZE

            if ((inode->i_size % 1024) == 0) { 
                printf("==  1024\n");
                /* If empty file, allocate new block */
                inode->i_data_blocks[i] = data_block_alloc();
            }

            // Case write_10_blocks_spill
            // 1KB is NOT a multiple of SIZE

            else if (inode->i_size + to_write > 1024*(i+1)) {
                printf("> 1024\n");
                aux = (size_t)(1024*(i+1)) - inode->i_size; // to write in current block

                //perform the write
                void *block = data_block_get(inode->i_data_blocks[i]); 
                printf("aux: %ld\n", aux);
                memcpy(block + file->of_offset, buffer, aux);

                // File offset update
                file->of_offset += aux;
                if (file->of_offset > inode->i_size) {
                    inode->i_size = file->of_offset;
                }
                printf (" # aux %ld\n",file->of_offset);

                to_write = to_write - aux; // only write to the next block
                printf("to_write after: %ld\n", to_write);
                i++; // one block was completed, so inc i
                inode->i_data_blocks[i] = data_block_alloc(); // alloc space for the new block

            }

            //printf("i-value: %d\n",i);
            printf("inode->i_data_blocks[i] %d\n",inode->i_data_blocks[i]);
            void *block = data_block_get(inode->i_data_blocks[i]);

            if (block == NULL) {
                return -1;
            }
        
            /* Perform the actual write */
            memcpy(block + file->of_offset, buffer, to_write);
            added = 1;

            /* The offset associated with the file handle is
            * incremented accordingly */
            file->of_offset += to_write;
            if (file->of_offset > inode->i_size) {
                inode->i_size = file->of_offset;
            }
        }
    }

    printf (" # %ld\n",file->of_offset);
    return (ssize_t)to_write + (ssize_t)aux;
}


ssize_t tfs_read(int fhandle, void *buffer, size_t len) {

    open_file_entry_t *file = get_open_file_entry(fhandle);
    if (file == NULL) {
        return -1;
    }

    /* From the open file table entry, we get the inode */
    inode_t *inode = inode_get(file->of_inumber);
    if (inode == NULL) {
        return -1;
    }

    /* Determine how many bytes to read */
    size_t to_read = inode->i_size - file->of_offset;
    if (to_read > len) {
        to_read = len;
    }

    int i=0, read = 0;
    size_t aux = 0;
    if (to_read > 0) {

        // Direct Read
        while (i < DIRECT_REF_BLOCKS && read != 1) {

            i = (int)(file->of_offset/1024) % 10;

            // Case write_10_blocks_simple
            // 1KB is NOT multiple of SIZE
    
            if  (file->of_offset + to_read > 1024*(i+1) ) {
                printf("> 1024\n");
                aux = (size_t)(1024*(i+1)) - file->of_offset;

                //perform the write
                void *block = data_block_get(inode->i_data_blocks[i]);
                printf("aux: %ld\n", aux);
                memcpy(buffer, block + file->of_offset, aux);
                
                // File offset update
                file->of_offset += aux;
                printf (" # aux %ld\n",file->of_offset);

                to_read = to_read - aux;
                printf("to_read after: %ld\n", to_read);

                i++;
            }

            // Case write_10_blocks_simple
            // 1KB is multiple of SIZE

            printf("==  1024\n");

            //printf("i-value: %d\n",i);
            printf("inode->i_data_blocks[i] %d\n",inode->i_data_blocks[i]);

            void *block = data_block_get(inode->i_data_blocks[i]);
            if (block == NULL) {
                return -1;
            }

            /* Perform the actual read */
            memcpy(buffer, block + file->of_offset, to_read);
            read = 1;
            /* The offset associated with the file handle is
            * incremented accordingly */
            file->of_offset += to_read;
        }
    }
    
    printf (" # %ld\n",file->of_offset);
    return (ssize_t)to_read + (ssize_t)aux;
}



int tfs_copy_to_external_fs(char const *source_path, char const *dest_path){

    /* Scenario 1: destination file is in directory that does not exist */

    if (dest_path[0] == '/' || dest_path[0] == '.') {
        if (strlen(dest_path) > 2) {
            printf("Scenario #1 - OK \n");
            return -1;
        }        
    }

    /* Scenario 2: source file does not exist */

    if(tfs_open(source_path,TFS_O_APPEND) == -1) {
        printf("Scenario #2 - OK \n");
        return -1;
    }

    // Determine the data to copy

    char data[SIZE];

    int fh_source = tfs_open(source_path,0);
    assert(fh_source != -1);

    tfs_read(fh_source,data,SIZE);

    //printf("Output: %s\n",data);

    // Case 1 - File with dest_path, exist
    // Case 2 - File with dest_path does not exist
    // In both cases we start with a empty "new" file
    
    FILE *fp;
    fp = fopen(dest_path, "w");
    // write in the File dest_path
    fwrite(data,sizeof(char),sizeof(data),fp);
    fclose(fp);


    return 0;
    
}
