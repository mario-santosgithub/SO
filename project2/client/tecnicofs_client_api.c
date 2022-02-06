#include "tecnicofs_client_api.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>


static int user_ID;
static char server_path[40];
static char client_path[MAX_PIPENAME];
static int server;
static int client;

int tfs_mount(char const *client_pipe_path, char const *server_pipe_path) {
    int client_id;
    size_t offset = 0;
    char buffer[sizeof(char)+(sizeof(char)*MAX_PIPENAME)];
    
    unlink(client_pipe_path);
		
    buffer[0] = TFS_OP_CODE_MOUNT;
    offset += sizeof(char);
    strcpy(buffer+offset,client_pipe_path);
    offset += strlen(client_pipe_path)+1;

    /* Create the current client's FIFO */
	if (mkfifo(client_pipe_path,0777) < 0) {
		exit(1);
    }

    server = open(server_pipe_path,O_WRONLY);
    if (server == -1) {return -1;}

    if(write(server,buffer,offset) == -1){
        return -1;
    }

    // Opens the client to read the return from the server
    client = open(client_pipe_path,O_RDONLY);

    // Reads from the client pipe the client's ID 
    if(read(client,&client_id,sizeof(int)) == -1){
        return -1;
    };

    user_ID = client_id;
    strcpy(server_path,server_pipe_path);
    strcpy(client_path,client_pipe_path);
    return 0;
}

int tfs_unmount() {
    size_t offset = 0;
    /* Buffer: (char)OP_CODE|(int)userID */
    char buffer[sizeof(char)+sizeof(int)]; 
    buffer[0] = TFS_OP_CODE_UNMOUNT;
    offset += sizeof(char);
    memcpy(buffer+offset,&user_ID,sizeof(int));
    offset += sizeof(int);

    /* Open the server pipe to write on it the user ID*/
    if(write(server,buffer,offset) == -1){return -1;}

    if(close(server) == -1){return -1;};
    if(close(client) == -1){return -1;};
    unlink(client_path);

    return 0;
}

int tfs_open(char const *name, int flags) {
    /* Buffer: (char)OP_CODE|(int)userID|(char[40])name|(int)flags*/
    size_t offset = 0;
    int return_value;
    char buffer[(sizeof(char)+2*sizeof(int))+(MAX_PIPENAME*sizeof(char))];
    buffer[0] = TFS_OP_CODE_OPEN;
    offset += sizeof(char);
    memcpy(buffer+offset,&user_ID,sizeof(int));
    offset += sizeof(int);
    strcpy(buffer+offset,name);
    size_t name_size = strlen(name)+1;
    offset += name_size;
    memcpy(buffer+offset,&flags,sizeof(int));
    offset += sizeof(int);
    
    
    /* Open the server pipe to write on it the userID/name/flags*/

    if(write(server,buffer,offset) == -1){return -1;}

    if(read(client,&return_value,sizeof(int)) == -1){return -1;}

    return return_value;

}

int tfs_close(int fhandle) {
    unsigned long offset=0;
    int return_value;
    char buffer[sizeof(char)+2*sizeof(int)]; 
    buffer[0] = TFS_OP_CODE_CLOSE;
    offset += sizeof(char);
    memcpy(buffer+offset,&user_ID,sizeof(int));
    offset += sizeof(int);
    memcpy(buffer+offset, &fhandle,sizeof(int));
    offset += sizeof(int);

    if(write(server,buffer,offset) == -1) {return -1;}

    if(read(client,&return_value,sizeof(int)) == -1){return -1;}

    return return_value;
}

ssize_t tfs_write(int fhandle, void const *buffer_write, size_t len) {
    
    /* Buffer: (char)OP_CODE|(int)userID|(int)fhandle|(size_t)len|char(len)buffer_write*/
    size_t offset=0;
    int write_return;
    char buffer[sizeof(char)+2*sizeof(int)+sizeof(size_t)+len*sizeof(char)];
    char buffer_len[sizeof(size_t)];
    ssize_t return_value;

    buffer[0] = TFS_OP_CODE_WRITE;
    offset += sizeof(char);
    memcpy(buffer+offset,&user_ID,sizeof(int));
    offset += sizeof(int);
    memcpy(buffer+offset,&fhandle,sizeof(int));
    offset += sizeof(int);
    memcpy(buffer+offset,&len,sizeof(size_t));
    memcpy(buffer_len,&len,sizeof(size_t));
    offset += sizeof(size_t);
    size_t buffer_write_size = strlen(buffer_write)+1;
    strcpy(buffer+offset,buffer_write);
    offset += buffer_write_size-1;


    if (write(server,buffer,offset) == -1) {return -1;}

    // Opens the client to read the return from the server
    
    if(read(client,&write_return,sizeof(int)) == -1){
        return -1;
    }

    return_value = (ssize_t)write_return;
    return return_value;

}

ssize_t tfs_read(int fhandle, void *buffer_read, size_t len) {
    
    size_t offset=0;
    int return_value;
    char buffer_return[len+sizeof(int)];

    /* (char) OP_CODE=6 | (int) session_id | (int) fhandle | (size_t) len */
    char buffer[sizeof(char)+2*sizeof(int)+sizeof(size_t)];
    buffer[0] = TFS_OP_CODE_READ;
    offset += sizeof(char);
    memcpy(buffer+offset,&user_ID,sizeof(int));
    offset += sizeof(int);
    memcpy(buffer+offset,&fhandle,sizeof(int));
    offset += sizeof(int);
    memcpy(buffer+offset,&len,sizeof(size_t));
    offset += sizeof(size_t);


    if(write(server,buffer,offset) == -1) {return -1;}
    

    // Opens the client to read the return from the server
    
    if(read(client,buffer_return,len+sizeof(int)) == -1){
        return -1;
    }

    memcpy(&return_value,buffer_return,sizeof(int));
    strncpy(buffer_read,buffer_return + sizeof(int),len);
    
    if (return_value == -1) {return -1;}
    return return_value;

}

int tfs_shutdown_after_all_closed() {
    /* Buffer: (char)OP_CODE | (int)userID */
    char buffer[sizeof(int)+sizeof(int)]; 
    buffer[0] = TFS_OP_CODE_SHUTDOWN_AFTER_ALL_CLOSED;
    memcpy(buffer+1,&user_ID,sizeof(int));
    /* Open the server pipe to write on it the user ID*/
    if(write(server,buffer,strlen(buffer)+1) == -1){return -1;}
    
    return 0;
}
