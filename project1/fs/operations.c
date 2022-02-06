#include "operations.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>


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
            pthread_rwlock_rdlock(&inode->rwlock);
            if (inode->i_size > 0) {
                for (int i=0; i < DIRECT_REF_BLOCKS; i++) {
                    if (data_block_free(inode->direct_blocks[i]) == -1) {
                        pthread_rwlock_unlock(&inode->rwlock);
                        return -1;
                    }
                }
                pthread_rwlock_wrlock(&inode->rwlock);
                inode->i_size = 0; 
                pthread_rwlock_unlock(&inode->rwlock);   
            }
            pthread_rwlock_unlock(&inode->rwlock);
        }

        pthread_rwlock_wrlock(&inode->rwlock);
        /* Determine initial offset */
        if (flags & TFS_O_APPEND) {
            offset = inode->i_size;
        } else {
            offset = 0;
        }
        pthread_rwlock_unlock(&inode->rwlock);
    
    } else if (flags & TFS_O_CREAT) {
        /* The file doesn't exist; the flags specify that it should be created*/
        /* Create inode */
        inum = inode_create(T_FILE);
        if (inum == -1) {
            return -1;
        }
        
        /* Add entry in the root directory */
        pthread_rwlock_wrlock(&inode_get(ROOT_DIR_INUM)->rwlock);
        if (add_dir_entry(ROOT_DIR_INUM, inum, name + 1) == -1) {
            inode_delete(inum);
            pthread_rwlock_unlock(&inode_get(ROOT_DIR_INUM)->rwlock);
            return -1;
        }
        pthread_rwlock_unlock(&inode_get(ROOT_DIR_INUM)->rwlock);

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
    pthread_mutex_lock(&file->mutex);
    /* Determine how many bytes to write */
    if (to_write + file->of_offset > BLOCK_SIZE*DIRECT_REF_BLOCKS + BLOCK_SIZE*INDIRECT_BLOCKS) {
        to_write = BLOCK_SIZE*DIRECT_REF_BLOCKS - file->of_offset;
    }


    size_t aux = 0, written = 0;
    if (to_write > 0) {
        pthread_rwlock_wrlock(&inode->rwlock);
        while (to_write != 0) {
            if (inode->i_size < BLOCK_SIZE*DIRECT_REF_BLOCKS) {

                int i = (int)(inode->i_size/BLOCK_SIZE) % 10;


                if ((inode->i_size % BLOCK_SIZE) == 0) { 
                    /* If empty file, allocate new block */
                    inode->direct_blocks[i] = data_block_alloc();
                }

                if (file->of_offset + to_write > BLOCK_SIZE*(i+1)) {
                    aux = (size_t)(BLOCK_SIZE*(i+1)) - file->of_offset;
                }
                else { aux = to_write; }

                void *block = data_block_get(inode->direct_blocks[i]);

                if (block == NULL) {
                    pthread_rwlock_unlock(&inode->rwlock);
                    pthread_mutex_unlock(&file->mutex);
                    return -1;
                }
                
                /* Perform the actual write */
                memcpy(block + file->of_offset%BLOCK_SIZE, buffer, aux);
                /* The offset associated with the file handle is
                * incremented accordingly */
                file->of_offset += aux;
                to_write -= aux;
                written += aux;
                if (file->of_offset > inode->i_size) {
                    inode->i_size = file->of_offset;
                }
            }
            else {
                if (inode->indirect_block == -1) {
                    inode->indirect_block = data_block_alloc();
                    int* indirect_blocks_p = data_block_get(inode->indirect_block);
                    for (int j = 0; j < INDIRECT_BLOCKS; j++){
                        indirect_blocks_p[j] = -1;
                    }
                }

                
                int i = (int)((file->of_offset-BLOCK_SIZE*DIRECT_REF_BLOCKS)/ BLOCK_SIZE) % 10;
                
        
                int* indirect_blocks_p = data_block_get(inode->indirect_block);

                if (((file->of_offset-BLOCK_SIZE*DIRECT_REF_BLOCKS) % BLOCK_SIZE) == 0) {
                    indirect_blocks_p[i] = data_block_alloc();
                }

                if (file->of_offset-BLOCK_SIZE*DIRECT_REF_BLOCKS + to_write > BLOCK_SIZE*(i+1)) {
                    aux = (size_t)(BLOCK_SIZE*(i+1)) - file->of_offset+BLOCK_SIZE*DIRECT_REF_BLOCKS;
                }
                else { aux = to_write; }


                void *block = data_block_get(indirect_blocks_p[i]);
                if (block == NULL) {
                    pthread_rwlock_unlock(&inode->rwlock);
                    pthread_mutex_unlock(&file->mutex);
                    return -1;
                }
                
                memcpy(block + file->of_offset%BLOCK_SIZE, buffer, aux);

                file->of_offset += aux;
                written += aux;
                to_write -= aux;
                if (file->of_offset > inode->i_size) {
                    inode->i_size = file->of_offset;
                }
            }   
        }
        pthread_rwlock_unlock(&inode->rwlock);
    }
    pthread_mutex_unlock(&file->mutex);
    return (ssize_t)to_write + (ssize_t)written;
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

    pthread_mutex_lock(&file->mutex);
    pthread_rwlock_rdlock(&inode->rwlock);
    /* Determine how many bytes to read */
    size_t to_read = inode->i_size - file->of_offset;
    if (to_read > len) {
        to_read = len;
    }

    size_t aux = 0, read = 0;
    if (to_read > 0) {
        while ( to_read != 0) {
            if (file->of_offset < BLOCK_SIZE*DIRECT_REF_BLOCKS) {
                    
                // Get inumber to read from
                int i = (int)(file->of_offset/BLOCK_SIZE) % 10;

            
                if  (file->of_offset + to_read > BLOCK_SIZE*(i+1) ) {
                    aux = (size_t)(BLOCK_SIZE*(i+1)) - file->of_offset;
                }
                else { aux = to_read; }


                void *block = data_block_get(inode->direct_blocks[i]);
                if (block == NULL) {
                    pthread_rwlock_unlock(&inode->rwlock);
                    pthread_mutex_unlock(&file->mutex);
                    return -1;
                }

                /* Perform the actual read */
                memcpy(buffer, block + file->of_offset%BLOCK_SIZE, aux);

                /* The offset associated with the file handle is
                * incremented accordingly */
                file->of_offset += aux; 
                to_read -= aux;
                read += aux;
            }
            else {
                int i = (int)((file->of_offset-BLOCK_SIZE*DIRECT_REF_BLOCKS)/BLOCK_SIZE) % 10;
                int* indirect_blocks_p = data_block_get(inode->indirect_block);
                
                if ((file->of_offset-BLOCK_SIZE*DIRECT_REF_BLOCKS) + to_read > BLOCK_SIZE*(i+1)) {
                    aux = (size_t)(BLOCK_SIZE*(i+1)) - file->of_offset+BLOCK_SIZE*DIRECT_REF_BLOCKS;
                }
                else { aux = to_read; }

                void *block = data_block_get(indirect_blocks_p[i]);
                if (block == NULL) {
                    pthread_rwlock_unlock(&inode->rwlock);
                    pthread_mutex_unlock(&file->mutex);
                    return -1;
                }

                memcpy(buffer, block + file->of_offset%BLOCK_SIZE, aux);

                file->of_offset += aux;
                to_read -= aux;
                read += aux;
            }  
        }
    }
    pthread_rwlock_unlock(&inode->rwlock);
    pthread_mutex_unlock(&file->mutex);    
    return (ssize_t)to_read + (ssize_t)read;
}




int tfs_copy_to_external_fs(char const *source_path, char const *dest_path){

    /* Scenario 1: destination file is in directory that does not exist */

    if (dest_path[0] == '/' || dest_path[0] == '.') {
        if (strlen(dest_path) > 2) {
            return -1;
        }        
    }

    /* Scenario 2: source file does not exist */

    if(tfs_open(source_path,TFS_O_APPEND) == -1) {
        return -1;
    }

    // Determine the data to copy

    char data[SIZE];

    int fh_source = tfs_open(source_path,0);
    assert(fh_source != -1);

    tfs_read(fh_source,data,SIZE);


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