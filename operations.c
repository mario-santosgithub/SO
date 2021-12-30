#include "operations.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

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
        return -1;
    }

    inum = tfs_lookup(name);
    if (inum >= 0) {
        /* The file already exists */
        inode_t *inode = inode_get(inum);
        if (inode == NULL) {
            return -1;
        }

        /* Trucate (if requested) */
        if (flags & TFS_O_TRUNC) {
            if (inode->i_size > 0) {

                for (int i=0; i < DIRECT_REF_BLOCKS; i++) {
                    if (data_block_free(inode->i_data_blocks[i]) == -1) {
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
            return -1;
        }
        /* Add entry in the root directory */
        if (add_dir_entry(ROOT_DIR_INUM, inum, name + 1) == -1) {
            inode_delete(inum);
            return -1;
        }
        offset = 0;
    } else {
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

    int i=0, added=0;
    if (to_write > 0) {

        while (i < DIRECT_REF_BLOCKS && added != 1) {

            
            if ((inode->i_size % 1024) == 0) { // se -1 o bloco n está ocupado
                int j=0;
                while (j < DIRECT_REF_BLOCKS) {
                    if (inode->i_data_blocks[i] != -1) {i++;}
                    j++;
                }
                 /* If empty file, allocate new block */
                inode->i_data_blocks[i] = data_block_alloc();
            }
            else {
                int j=0;
                while (j < DIRECT_REF_BLOCKS) {
                    if (inode->i_data_blocks[i] != -1) {i++;}
                    j++;
                }
                i--;
            }

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

    return (ssize_t)to_write;
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
    
    printf("To read value = %ld\n",to_read);

    int i=0;
    if (to_read > 0) {

        printf("Current file->of_offset: %ld\n",file->of_offset);

        //  Case write_10_blocks_simple
        //  1KB is a multiple of SIZE=256    

        if (1024 % to_read == 0) {

            // Determine the block to read from:
            // In this case it has to go next block to read

            // Base case
            if((file->of_offset % 1024) == 0) {
                i = (int)file->of_offset / 1024;
            }

            // Case bigger 1024
            if(file->of_offset > 1024) {
                // Case multiply 1024
                if((file->of_offset % 1024) == 0) {
                    i = (int)file->of_offset / 1024;
                }
                // Case not mul 1024 but bigger 
                else {
                    i = (int)file->of_offset / 1024;
                }

            }

            //printf ("Current i value: %d\n",i);
     
            printf("inode->i_data_blocks[i] %d\n",inode->i_data_blocks[i]);
            void *block = data_block_get(inode->i_data_blocks[i]);

            if (block == NULL) {
                return -1;
            }

            /* Perform the actual read */
            memcpy(buffer, block + file->of_offset, to_read);

            /* The offset associated with the file handle is
            * incremented accordingly */
            file->of_offset += to_read;
            printf (" # %ld\n",file->of_offset);
        }
        
        //  Case write_10_blocks_spill
        //  1KB is NOT a multiple of SIZE=256
        
        else {

            // Determine the block to read from:
            // In this case it has to go next block to read

            // Base case
            if((file->of_offset % 1024) == 0) {
                i = (int)file->of_offset / 1024;
            }

            // Case bigger 1024
            if(file->of_offset > 1024) {
                // Case multiply 1024
                if((file->of_offset % 1024) == 0) {
                    i = (int)file->of_offset / 1024;
                }
                // Case not mul 1024 but bigger 
                else {
                    i = (int)file->of_offset / 1024;
                }

            }

            printf ("Current i value: %d\n",i);
     
            printf("inode->i_data_blocks[i] %d\n",inode->i_data_blocks[i]);
            void *block = data_block_get(inode->i_data_blocks[i]);

            if (block == NULL) {
                return -1;
            }

            // Case when it cannot perform the read
            if ((file->of_offset + to_read) > (i+1) * 1024) {
                int left_to_read = (int)(file->of_offset + to_read) - (i+1)*1024;
                printf ("Value left to read: %d\n",left_to_read);
                int to_read_left = (int)to_read - left_to_read;
                printf("Value to write: %d \n", to_read_left);
                /* Perform the actual read */
                memcpy(buffer, block + (size_t)to_read_left, to_read);
                /* The offset associated with the file handle is
                * incremented accordingly */
                file->of_offset += (size_t)to_read_left;
                to_read += (size_t)left_to_read;

            }

            else {

                /* Perform the actual read */
                memcpy(buffer, block + file->of_offset, to_read);
                /* The offset associated with the file handle is
                * incremented accordingly */
                file->of_offset += to_read;
            }

            printf (" # %ld\n",file->of_offset);

            //printf ("CASE 2 \n");
            //return -1;
        }

    }
    
    return (ssize_t)to_read;
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
