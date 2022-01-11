#include "state.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

/* Persistent FS state  (in reality, it should be maintained in secondary
 * memory; for simplicity, this project maintains it in primary memory) */

/* I-node table */
static inode_t inode_table[INODE_TABLE_SIZE];
static char freeinode_ts[INODE_TABLE_SIZE];
pthread_mutex_t mutex_inode_table = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_freeinode_ts = PTHREAD_MUTEX_INITIALIZER;

/* Data blocks */
static char fs_data[BLOCK_SIZE * DATA_BLOCKS];
static char free_blocks[DATA_BLOCKS];
pthread_mutex_t mutex_fs_data = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_free_blocks = PTHREAD_MUTEX_INITIALIZER;

/* Volatile FS state */

static open_file_entry_t open_file_table[MAX_OPEN_FILES];
static char free_open_file_entries[MAX_OPEN_FILES];
pthread_mutex_t mutex_open_file_table = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_free_open_file_entries = PTHREAD_MUTEX_INITIALIZER;

static inline bool valid_inumber(int inumber) {
    return inumber >= 0 && inumber < INODE_TABLE_SIZE;
}

static inline bool valid_block_number(int block_number) {
    return block_number >= 0 && block_number < DATA_BLOCKS;
}

static inline bool valid_file_handle(int file_handle) {
    return file_handle >= 0 && file_handle < MAX_OPEN_FILES;
}

/**
 * We need to defeat the optimizer for the insert_delay() function.
 * Under optimization, the empty loop would be completely optimized away.
 * This function tells the compiler that the assembly code being run (which is
 * none) might potentially change *all memory in the process*.
 *
 * This prevents the optimizer from optimizing this code away, because it does
 * not know what it does and it may have side effects.
 *
 * Reference with more information: https://youtu.be/nXaxk27zwlk?t=2775
 *
 * Exercise: try removing this function and look at the assembly generated to
 * compare.
 */
static void touch_all_memory() { __asm volatile("" : : : "memory"); }

/*
 * Auxiliary function to insert a delay.
 * Used in accesses to persistent FS state as a way of emulating access
 * latencies as if such data structures were really stored in secondary memory.
 */
static void insert_delay() {
    for (int i = 0; i < DELAY; i++) {
        touch_all_memory();
    }
}

/*
 * Initializes FS state
 */
void state_init() {
    for (size_t i = 0; i < INODE_TABLE_SIZE; i++) {
        freeinode_ts[i] = FREE;
    }

    for (size_t i = 0; i < DATA_BLOCKS; i++) {
        free_blocks[i] = FREE;
    }

    for (size_t i = 0; i < MAX_OPEN_FILES; i++) {
        free_open_file_entries[i] = FREE;
    }
}

void state_destroy() { /* nothing to do */
}

/*
 * Creates a new i-node in the i-node table.
 * Input:
 *  - n_type: the type of the node (file or directory)
 * Returns:
 *  new i-node's number if successfully created, -1 otherwise
 */
int inode_create(inode_type n_type) {
    printf("inode_create: Entry\n");
    for (int inumber = 0; inumber < INODE_TABLE_SIZE; inumber++) {
        
        if ((inumber * (int) sizeof(allocation_state_t) % BLOCK_SIZE) == 0) {
            insert_delay(); // simulate storage access delay (to freeinode_ts)
        }

        pthread_mutex_lock(&mutex_freeinode_ts); //Lock1;
        /* Finds first free entry in i-node table */
        if (freeinode_ts[inumber] == FREE) {
            /* Found a free entry, so takes it for the new i-node*/
            freeinode_ts[inumber] = TAKEN;
            insert_delay(); // simulate storage access delay (to i-node)
            
            pthread_mutex_lock(&mutex_inode_table);
            inode_table[inumber].i_node_type = n_type;

            if (n_type == T_DIRECTORY) {
                /* Initializes directory (filling its block with empty
                 * entries, labeled with inumber==-1) */
                
                int b = data_block_alloc();

                if (b == -1) {
                    freeinode_ts[inumber] = FREE;
                    pthread_mutex_unlock(&mutex_freeinode_ts);
                    pthread_mutex_unlock(&mutex_inode_table);
                    printf("inode_create: Leave\n");
                    return -1;
                }

                pthread_mutex_unlock(&mutex_freeinode_ts);
                inode_table[inumber].i_size = BLOCK_SIZE;
                

                for(int i=0; i < DIRECT_REF_BLOCKS; i++) {
                    inode_table[inumber].direct_blocks[i] = b;
                }

                pthread_mutex_unlock(&mutex_inode_table);

                dir_entry_t *dir_entry = (dir_entry_t *)data_block_get(b);
                if (dir_entry == NULL) {
                    freeinode_ts[inumber] = FREE;
                    pthread_mutex_unlock(&mutex_freeinode_ts);
                    printf("inode_create: Leave\n");
                    return -1;
                }

                for (size_t i = 0; i < MAX_DIR_ENTRIES; i++) {
                    dir_entry[i].d_inumber = -1;
                } 

            } else {
                pthread_mutex_unlock(&mutex_freeinode_ts);
            
                /* In case of a new file, simply sets its size to 0 */
                
                inode_table[inumber].i_size = 0;
                
                // Direct Reference Blocks
                for(int i=0; i < DIRECT_REF_BLOCKS; i++) { 
                    inode_table[inumber].direct_blocks[i] = -1;
                }

                inode_table[inumber].indirect_block = -1;

                
                pthread_mutex_unlock(&mutex_inode_table);
                
            }
            printf("inode_create: Leave\n");
            return inumber;
        }
        
        pthread_mutex_unlock(&mutex_freeinode_ts);

    }
    printf("inode_create: Leave\n");
    return -1;
}


/*
 * Deletes the i-node.
 * Input:
 *  - inumber: i-node's number
 * Returns: 0 if successful, -1 if failed
 */
int inode_delete(int inumber) {
    printf("inode_delete: Entry\n");
    // simulate storage access delay (to i-node and freeinode_ts)
    insert_delay();
    insert_delay();

    pthread_mutex_lock(&mutex_freeinode_ts);

    if (!valid_inumber(inumber) || freeinode_ts[inumber] == FREE) {
        pthread_mutex_unlock(&mutex_freeinode_ts);
        printf("inode_delete: Leave\n");
        return -1;
    }

    freeinode_ts[inumber] = FREE;

    pthread_mutex_unlock(&mutex_freeinode_ts);

    pthread_mutex_lock(&mutex_inode_table);
    if (inode_table[inumber].i_size > 0) { 
        
        if (data_blocks_free(inode_table[inumber].direct_blocks) == -1) {
            pthread_mutex_unlock(&mutex_inode_table);
            printf("inode_delete: Leave\n");
            return -1;
        }
        int* indirect_block_p = data_block_get(inode_table[inumber].indirect_block);
        pthread_mutex_unlock(&mutex_inode_table);

        for (int i = 0; i < INDIRECT_BLOCKS; i++){
            if(data_block_free(indirect_block_p[i] == -1)) {
                printf("inode_delete: Leave\n");
                return -1;
            }
        }

    }
    printf("inode_delete: Leave\n");
    return 0;
}

/*
 * Returns a pointer to an existing i-node.
 * Input:
 *  - inumber: identifier of the i-node
 * Returns: pointer if successful, NULL if failed
 */
inode_t *inode_get(int inumber) {
    printf("inode_get: Entry\n");
    if (!valid_inumber(inumber)) {
        return NULL;
    }

    insert_delay(); // simulate storage access delay to i-node
    printf("inode_get: Leave\n");
    return &inode_table[inumber];
}

/*
 * Adds an entry to the i-node directory data.
 * Input:
 *  - inumber: identifier of the i-node
 *  - sub_inumber: identifier of the sub i-node entry
 *  - sub_name: name of the sub i-node entry
 * Returns: SUCCESS or FAIL
 */
int add_dir_entry(int inumber, int sub_inumber, char const *sub_name) {
    printf("add_dir_entry: Entry\n");
    if (!valid_inumber(inumber) || !valid_inumber(sub_inumber)) {
        printf("add_dir_entry: Leave\n");
        return -1;
    }

    insert_delay(); // simulate storage access delay to i-node with inumber
    pthread_mutex_lock(&mutex_inode_table);
    if (inode_table[inumber].i_node_type != T_DIRECTORY) {
        pthread_mutex_unlock(&mutex_inode_table);
        printf("add_dir_entry: Leave\n");
        return -1;
    }

    if (strlen(sub_name) == 0) {
        pthread_mutex_unlock(&mutex_inode_table);
        printf("add_dir_entry: Leave\n");
        return -1;
    }

    // Direct reference blocks

    for(int j=0; j < DIRECT_REF_BLOCKS; j++) {
        /* Locates the block containing the directory's entries */
        //pthread_mutex_lock(&inode_table[inumber].mutex);
        dir_entry_t *dir_entry =
            (dir_entry_t *)data_block_get(inode_table[inumber].direct_blocks[j]);
        if (dir_entry == NULL) {
            pthread_mutex_unlock(&mutex_inode_table);
            printf("add_dir_entry: Leave\n");
            return -1;
        }

        /* Finds and fills the first empty entry */
        for (size_t i = 0; i < MAX_DIR_ENTRIES; i++) {
            if (dir_entry[i].d_inumber == -1) {
                dir_entry[i].d_inumber = sub_inumber;
                strncpy(dir_entry[i].d_name, sub_name, MAX_FILE_NAME - 1);
                dir_entry[i].d_name[MAX_FILE_NAME - 1] = 0;
                pthread_mutex_unlock(&mutex_inode_table);
                printf("add_dir_entry: Leave\n");
                return 0;
            }
        }  
    }

    // Indirect blocks

    int* indirect_block_p = data_block_get(inode_table[inumber].indirect_block);
    pthread_mutex_unlock(&mutex_inode_table);

    for(int j=0; j < INDIRECT_BLOCKS; j++) {

        /* Locates the block containing the directory's entries */
        dir_entry_t *dir_entry =
            (dir_entry_t *)data_block_get(indirect_block_p[j]);
        if (dir_entry == NULL) {
            printf("add_dir_entry: Leave\n");
            return -1;
        }

        /* Finds and fills the first empty entry */
        for (size_t i = 0; i < MAX_DIR_ENTRIES; i++) {
            if (dir_entry[i].d_inumber == -1) {
                dir_entry[i].d_inumber = sub_inumber;
                strncpy(dir_entry[i].d_name, sub_name, MAX_FILE_NAME - 1);
                dir_entry[i].d_name[MAX_FILE_NAME - 1] = 0;
                printf("add_dir_entry: Leave\n");
                return 0;
            }
        }
        
    }
    printf("add_dir_entry: Leave\n");
    return -1;
}

/* Looks for a given name inside a directory
 * Input:
 * 	- parent directory's i-node number
 * 	- name to search
 * 	Returns i-number linked to the target name, -1 if not found
 */
int find_in_dir(int inumber, char const *sub_name) {
    printf("find_in_dir: Entry\n");
    insert_delay(); // simulate storage access delay to i-node with inumber

    pthread_mutex_lock(&mutex_inode_table);
    if (!valid_inumber(inumber) ||
        inode_table[inumber].i_node_type != T_DIRECTORY) {
        pthread_mutex_unlock(&mutex_inode_table);
        printf("find_in_dir: Leave\n");
        return -1;
    }
    pthread_mutex_unlock(&mutex_inode_table);
    pthread_mutex_lock(&mutex_inode_table);

    // Direct reference blocks
    /* Locates the block containing the directory's entries */
    /* Iterates over the directory entries looking for one that has the target
    * name */


    for (int j=0; j < DIRECT_REF_BLOCKS; j++) {

        /* Locates the block containing the directory's entries */
        dir_entry_t *dir_entry =
            (dir_entry_t *)data_block_get(inode_table[inumber].direct_blocks[j]);
        if (dir_entry == NULL) {
            pthread_mutex_unlock(&mutex_inode_table);
            printf("find_in_dir: Leave\n");
            return -1;
        }
 
        for (int i = 0; i < MAX_DIR_ENTRIES; i++) {
            if ((dir_entry[i].d_inumber != -1) &&
                (strncmp(dir_entry[i].d_name, sub_name, MAX_FILE_NAME) == 0)) {
                return dir_entry[i].d_inumber;
            }
        }
    }

    // Indirect reference blocks
    /* Locates the block containing the directory's entries */
    /* Iterates over the directory entries looking for one that has the target
    * name */

    int* indirect_block_p = data_block_get(inode_table[inumber].indirect_block);
    pthread_mutex_unlock(&mutex_inode_table);
    for (int j=0; j < INDIRECT_BLOCKS; j++) {
        dir_entry_t *dir_entry =
            (dir_entry_t *)data_block_get(indirect_block_p[j]);
        if (dir_entry == NULL) {
            printf("find_in_dir: Leave\n");
            return -1;
        }
        
        for (int i = 0; i < MAX_DIR_ENTRIES; i++) {
            if ((dir_entry[i].d_inumber != -1) &&
                (strncmp(dir_entry[i].d_name, sub_name, MAX_FILE_NAME) == 0)) {
                return dir_entry[i].d_inumber;
            }
        }
    }
    printf("find_in_dir: Leave\n");
    return -1;
}

/*
 * Allocated a new data block
 * Returns: block index if successful, -1 otherwise
 */
int data_block_alloc() {
    printf("data_block_alloc: Entry\n");
    for (int i = 0; i < DATA_BLOCKS; i++) {
        if (i * (int) sizeof(allocation_state_t) % BLOCK_SIZE == 0) {
            insert_delay(); // simulate storage access delay to free_blocks
        }

        pthread_mutex_lock(&mutex_free_blocks);
        if (free_blocks[i] == FREE) {
            free_blocks[i] = TAKEN;
            pthread_mutex_unlock(&mutex_free_blocks);
            printf("data_block_alloc: Leave\n");
            return i;
        }
        pthread_mutex_unlock(&mutex_free_blocks);
    }
    printf("data_block_alloc: Leave\n");
    return -1;
}

/* Frees a data block
 * Input
 * 	- the block index
 * Returns: 0 if success, -1 otherwise
 */
int data_block_free(int block_number) {
    printf("data_block_free: Entry\n");
    if (!valid_block_number(block_number)) {
        printf("data_block_free: leave\n");
        return -1;
    }

    insert_delay(); // simulate storage access delay to free_blocks
    pthread_mutex_lock(&mutex_free_blocks);
    free_blocks[block_number] = FREE;
    pthread_mutex_unlock(&mutex_free_blocks);
    printf("data_block_free: leave\n");

    return 0;
}


/* Frees all i-node blocks
 * Input
 *  - the array with the i-node blocks
 * Returns: 0 if success, -1 otherwise
 */
int data_blocks_free(int blocks[]) {
    printf("data_blocks_free: Entry\n");
    
    for(int i=0; i < DIRECT_REF_BLOCKS; i++) {
        if (!valid_block_number(blocks[i])) {
            printf("data_blocks_free: leave\n");
            return -1;
        }
    }
    pthread_mutex_lock(&mutex_free_blocks);

    for(int i=0; i < DIRECT_REF_BLOCKS; i++) {
        insert_delay(); // simulate storage access delay to free_blocks
        free_blocks[blocks[i]] = FREE;
    }

    pthread_mutex_unlock(&mutex_free_blocks);
    printf("data_blocks_free: leave\n");

    return 0;
}





/* Returns a pointer to the contents of a given block
 * Input:
 * 	- Block's index
 * Returns: pointer to the first byte of the block, NULL otherwise
 */
void *data_block_get(int block_number) {
    printf("data_block_get: Entry\n");

    // # Comment
    if (block_number != 0){
        printf("block number: %d\n", block_number);
    }
    // # Comment - END

    if (!valid_block_number(block_number)) {
        printf("invalid number\n");
        printf("data_block_get: Leave\n");
        return NULL;
    }

    insert_delay(); // simulate storage access delay to block
    printf("data_block_get: Leave\n");
    return &fs_data[block_number * BLOCK_SIZE];
}

/* Add new entry to the open file table
 * Inputs:
 * 	- I-node number of the file to open
 * 	- Initial offset
 * Returns: file handle if successful, -1 otherwise
 */
int add_to_open_file_table(int inumber, size_t offset) {
    printf("add_to_open_file_table: Entry\n");
    pthread_mutex_lock(&mutex_free_open_file_entries);
    pthread_mutex_lock(&mutex_open_file_table);
    for (int i = 0; i < MAX_OPEN_FILES; i++) {
        if (free_open_file_entries[i] == FREE) {
            free_open_file_entries[i] = TAKEN;
            open_file_table[i].of_inumber = inumber;
            open_file_table[i].of_offset = offset;
            pthread_mutex_unlock(&mutex_free_open_file_entries);
            pthread_mutex_unlock(&mutex_open_file_table);
             printf("add_to_open_file_table: Leave\n");
            return i;
        }
    }
    pthread_mutex_unlock(&mutex_free_open_file_entries);
    pthread_mutex_unlock(&mutex_open_file_table);
    printf("add_to_open_file_table: Leave\n");
    return -1;
}

/* Frees an entry from the open file table
 * Inputs:
 * 	- file handle to free/close
 * Returns 0 is success, -1 otherwise
 */
int remove_from_open_file_table(int fhandle) {
    printf("remove_open_file_table: entry\n");
    pthread_mutex_lock(&mutex_free_open_file_entries);
    if (!valid_file_handle(fhandle) ||
        free_open_file_entries[fhandle] != TAKEN) {
        pthread_mutex_unlock(&mutex_free_open_file_entries);
        printf("remove_open_file_table: leave\n");
        return -1;
    }
    free_open_file_entries[fhandle] = FREE;
    pthread_mutex_unlock(&mutex_free_open_file_entries);
    printf("remove_open_file_table: leave\n");
    return 0;
}

/* Returns pointer to a given entry in the open file table
 * Inputs:
 * 	 - file handle
 * Returns: pointer to the entry if sucessful, NULL otherwise
 */
open_file_entry_t *get_open_file_entry(int fhandle) {
    if (!valid_file_handle(fhandle)) {
        return NULL;
    }
    return &open_file_table[fhandle];
}
