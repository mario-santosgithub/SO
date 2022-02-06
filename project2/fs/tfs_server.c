/* 
	SO project 2021/2022
	group 28: Mario Santos (99275) and Pedro Cruz (99297)
*/

#include "operations.h"
#include "tecnicofs_client_api.h"
#include <unistd.h> 
#include <sys/stat.h> 
#include <fcntl.h> 
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>

#define BUFFER_SIZE 128

/* Fuctions to read the arguments given from the client */
int server_tfs_unmount_struct(char *buffer);
int server_tfs_open_struct(char *buffer);
int server_tfs_close_struct(char *buffer);
int server_tfs_write_struct(int server);
int server_tfs_read_struct(char *buffer);
int server_tfs_shutdown_after_all_closed_struct(char *buffer);

/* Fuctions to process the client's requests */
int server_tfs_mount(char *client_pipe_path);
int server_tfs_unmount(int userID);
int server_tfs_open(int userID, char name[MAX_PIPENAME],int flags);
int server_tfs_close(int userID, int fhandle);
int server_tfs_write(int userID, int fhandle, size_t len,char *buffer);
int server_tfs_read(int userID, int fhandle, size_t len);
int server_tfs_shutdown_after_all_closed_struct(char *buffer);
int server_tfs_shutdown_after_all_closed(int userID);

void* process_threads(void *ptr);


typedef struct {
	char OP_CODE;
	int sessionID;
	char name[MAX_PIPENAME];
	int flags;
	int fhandle;
	size_t len;
	char buffer_write[BUFFER_SIZE];
	void *buffer_read;

} arguments;

/* Keeps track of the current active sessions in the server*/
static int current_sessionID = 0;

/* Save the client's pipe open int value */
static int clientPipes[S];

static int threads_flags[S];
static arguments args[S];

static pthread_t threads[S];
static pthread_cond_t pthread_cond[S];
static pthread_mutex_t pthread_mutex[S];
static pthread_mutex_t mutex;




/* Main funtion of tfs_server */
int main(int argc, char **argv) {
    int server;
	ssize_t read_OPCODE;
	char buffer[BUFFER_SIZE];
	char char_OPCODE; 
	int loop = 1;
	int userID = 0;
	
	/* initialize pipes and mutexes */
	for (int i = 0; i < S ; i++){
		threads_flags[i] = 0;
		args[i].sessionID = i;
		clientPipes[i] = -1;
		if (pthread_cond_init(&pthread_cond[i],0) != 0) {return -1;}
		if (pthread_mutex_init(&pthread_mutex[i],0) != 0) {return -1;}
		if (pthread_create(&threads[i],NULL,&process_threads,&args[i]) != 0){return -1;}
	}

	if(pthread_mutex_init(&mutex,0) != 0) {return -1;}

	/* Check if two paths are given */
    if (argc < 2) {
        printf("Please specify the pathname of the server's pipe.\n");
        return 1;
    }


    char *server_pipename = argv[1];
    printf("Starting TecnicoFS server with pipe called %s\n", server_pipename);

    unlink(server_pipename);
    
    /* Create the server's pipe with pathname */
    if(mkfifo(server_pipename,0777) < 0) {
		printf("Error mkfifo server_pipe_path\n");
    	exit(1); 
	}

	/* Flag that stops error from broken pipes */
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		return -1;
	}

    if(tfs_init() != 0){ 
        return -1;
    }

	/* Open the server pipe in order to process the request from the clients */
	server = open(server_pipename,O_RDONLY);
	if (server == -1) {return -1;}

	// Switch case to read arguments

	while(loop == 1){

		/* Read from the server's pipe the OP_CODE */
		read_OPCODE = read(server,buffer,sizeof(char));
	
		if (read_OPCODE == 0) {
			close(server);
			server = open(server_pipename,O_RDONLY);
			continue;
		}
		
		else if (read_OPCODE == -1) {return -1;}

		char_OPCODE = buffer[0];
		switch (char_OPCODE)
		{
		case TFS_OP_CODE_MOUNT:
			if(read(server,buffer,sizeof(char)*MAX_PIPENAME) == -1){return -1;};
			server_tfs_mount(buffer);
			break;

		case TFS_OP_CODE_UNMOUNT:
			if(read(server,buffer,sizeof(int)) == -1){return -1;};
			userID = server_tfs_unmount_struct(buffer);
			break;

		case TFS_OP_CODE_OPEN:
			if(read(server,buffer,(3*sizeof(int))+(40*sizeof(char))) == -1){return -1;}
			userID = server_tfs_open_struct(buffer);
			break;

		case TFS_OP_CODE_CLOSE:
			if(read(server, buffer,(3*sizeof(int))) == -1) {return -1;}
			userID = server_tfs_close_struct(buffer);
			break;

		case TFS_OP_CODE_WRITE:
			userID = server_tfs_write_struct(server);
			break;

		case TFS_OP_CODE_READ:
			if(read(server, buffer,(2*sizeof(int))+sizeof(size_t)) == -1) {return -1;};
			userID = server_tfs_read_struct(buffer);
			break;
			
		case TFS_OP_CODE_SHUTDOWN_AFTER_ALL_CLOSED:
			if(read(server, buffer,(2*sizeof(int))) == -1){return -1;};
			userID = server_tfs_shutdown_after_all_closed_struct(buffer);
			/* Break loop */
			loop--;
			break;
		default:
			break;
		}
		if (char_OPCODE != TFS_OP_CODE_MOUNT) {
			/* Signal to process the threads */
			pthread_mutex_lock(&pthread_mutex[userID]);
			threads_flags[userID] = 1;
			pthread_cond_signal(&pthread_cond[userID]);
			pthread_mutex_unlock(&pthread_mutex[userID]);
		}
	};
    unlink(server_pipename);
    return 0;
}


void* process_threads(void *ptr) {
	while (1) {
		pthread_mutex_lock(&pthread_mutex[((arguments*)ptr)->sessionID]);
		/* Wait until it has a process to */
    	while (threads_flags[((arguments*)ptr)->sessionID] != 1){
        	pthread_cond_wait(&pthread_cond[((arguments*)ptr)->sessionID],&pthread_mutex[((arguments*)ptr)->sessionID]);
    	}
    	pthread_mutex_unlock(&pthread_mutex[((arguments*)ptr)->sessionID]);
		switch (((arguments*)ptr)->OP_CODE)
		{
		case TFS_OP_CODE_UNMOUNT:
			server_tfs_unmount(((arguments*)ptr)->sessionID);
			break;
		case TFS_OP_CODE_OPEN:
			server_tfs_open(((arguments*)ptr)->sessionID,((arguments*)ptr)->name,((arguments*)ptr)->flags);
			break;
		case TFS_OP_CODE_CLOSE:
			server_tfs_close(((arguments*)ptr)->sessionID,((arguments*)ptr)->fhandle);
			break;
		case TFS_OP_CODE_WRITE:
			server_tfs_write(((arguments*)ptr)->sessionID,((arguments*)ptr)->fhandle,((arguments*)ptr)->len,((arguments*)ptr)->buffer_write);
			break;
		case TFS_OP_CODE_READ:
			server_tfs_read(((arguments*)ptr)->sessionID,((arguments*)ptr)->fhandle,((arguments*)ptr)->len);
			break;
		case TFS_OP_CODE_SHUTDOWN_AFTER_ALL_CLOSED:
			server_tfs_shutdown_after_all_closed(((arguments*)ptr)->sessionID);
			exit(0);
			break;
		default:
			break;
		}
		
		/* Signal to start waiting again */
		pthread_mutex_lock(&pthread_mutex[((arguments*)ptr)->sessionID]);
		threads_flags[((arguments*)ptr)->sessionID] = 0;
		pthread_mutex_unlock(&pthread_mutex[((arguments*)ptr)->sessionID]);
	}

}

int server_tfs_mount(char *client_pipe_path){
	/* Buffer: (char)OPCODE|(char[MAX_PIPENAME])pipename */
	int client;
	pthread_mutex_lock(&mutex);
	if (current_sessionID+1 < S) {	
		client = open(client_pipe_path,O_WRONLY);
		current_sessionID++;
		clientPipes[current_sessionID] = client;
		if (write(client,&current_sessionID,sizeof(int)) == -1) {
			
			pthread_mutex_unlock(&mutex);
			return -1; 
		}
		else {
			pthread_mutex_unlock(&mutex);
			return 0;
		}
	}
	else
	{	
		pthread_mutex_unlock(&mutex);
		return -1;
	}
}

int server_tfs_unmount_struct(char *buffer){
	size_t offset = 0;

	int userID = buffer[0];
	offset += sizeof(int);

	args[userID].OP_CODE = TFS_OP_CODE_UNMOUNT;
	args[userID].sessionID = userID;

	return userID;
}

int server_tfs_unmount(int userID){
	int client;
	int return_value;

	/* Obtain the client's file descriptor in order to close it*/
	client = clientPipes[userID];

	return_value = close(client);

	/* Write on Client's PIPE the return value */

	pthread_mutex_lock(&mutex);
	if (return_value != -1) {
		clientPipes[userID] = -1;
		current_sessionID--;
	}
	else 
	{
		pthread_mutex_unlock(&mutex);
		return -1;
	}
	pthread_mutex_unlock(&mutex);
	
	return 0;
}

int server_tfs_open_struct(char *buffer){
	size_t offset = 0;

	int userID = buffer[0];
	offset += sizeof(int);

	args[userID].OP_CODE = TFS_OP_CODE_OPEN;
	args[userID].sessionID = userID;
	strcpy(args[userID].name,buffer+offset);
	
	size_t name_size = strlen(args[userID].name)+1;
	offset += name_size;

	int flag = buffer[offset];
	args[userID].flags = flag;
	offset += sizeof(int);

	return userID;
}

int server_tfs_open(int sessionID, char name[MAX_PIPENAME], int flags) {
	int client;
	int return_value = tfs_open(name,flags);

	if (return_value == -1){return -1;}

	client = clientPipes[sessionID];

	if (write(client,&return_value,sizeof(int)) == -1) {
		return -1; 
	}
	return 0;
}

int server_tfs_close_struct(char *buffer){
	size_t offset = 0;

	int userID = buffer[0];
	offset += sizeof(int);

	args[userID].OP_CODE = TFS_OP_CODE_CLOSE;
	args[userID].sessionID = userID;
	args[userID].fhandle = buffer[offset];

	return userID;
	
}

int server_tfs_close(int sessionID, int fhandle) {
	int client;

	int return_value = tfs_close(fhandle);
	if (return_value == -1){return -1;}

	client = clientPipes[sessionID];
	if (write(client,&return_value,sizeof(int)) == -1) {
		return -1;
	}
	return 0;

}

int server_tfs_write_struct(int server) { 
	int userID;

	if (read(server,&userID,sizeof(int)) == -1) {return -1;}
	args[userID].sessionID = userID;
	args[userID].OP_CODE = TFS_OP_CODE_WRITE;
	if (read(server,&args[userID].fhandle,sizeof(int)) == -1) {return -1;}
	if (read(server,&args[userID].len,sizeof(size_t)) == -1) {return -1;}
	if (read(server,args[userID].buffer_write,sizeof(char)*args[userID].len) == -1) {return -1;}
	return userID;

}

int server_tfs_write(int sessionID, int fhandle, size_t len,char *buffer) {
	int client;

	ssize_t return_value;
	return_value = tfs_write(fhandle,buffer,len);
	if (return_value == -1){return -1;}

	client = clientPipes[sessionID];

	if (write(client,&return_value,sizeof(int)) == -1) {
		return -1; 
	}

	return 0;
}

int server_tfs_read_struct(char *buffer) {
	size_t offset = 0;
	int userID = buffer[0];
	offset += sizeof(int);

	args[userID].OP_CODE = TFS_OP_CODE_READ;
	args[userID].sessionID = userID;
	args[userID].fhandle = buffer[offset];

	offset += sizeof(int);
	args[userID].len = (size_t)buffer[offset];
	return userID;
}

int server_tfs_read(int sessionID, int fhandle, size_t len) {
	int client;
	int return_value;
	char to_read[len];
	char buffer_return[sizeof(int)+(sizeof(char)*len)];


	return_value = (int)tfs_read(fhandle,to_read,len);
	if (return_value == -1){return -1;}

	/* Build buffer_return */
	memcpy(buffer_return,&return_value,sizeof(int));
	strncpy(buffer_return + sizeof(int),to_read,len);

	client = clientPipes[sessionID];

	if (write(client,buffer_return,len + sizeof(int)) == -1) {
		return -1; 
	}
	return 0;
}

int server_tfs_shutdown_after_all_closed_struct(char *buffer) { 
	
	size_t offset = 0;

	int userID = buffer[0];
	offset += sizeof(int);
	
	args[userID].OP_CODE = TFS_OP_CODE_SHUTDOWN_AFTER_ALL_CLOSED;
	args[userID].sessionID = userID;

	return userID;
}

int server_tfs_shutdown_after_all_closed(int sessionID) {
	int client;
	
	int return_value = tfs_destroy_after_all_closed();
	if (return_value == -1){return -1;}

	client = clientPipes[sessionID];

	if (write(client,&return_value,sizeof(ssize_t)) == -1) {
		return -1;
	}
	if(pthread_mutex_destroy(&mutex) != 0) {return -1;}

	for (int i = 0; i < S ; i++){
		threads_flags[i] = 0;
		args[i].sessionID = i;
		clientPipes[i] = -1;
		if (pthread_cond_destroy(&pthread_cond[i]) != 0) {return -1;}
		if (pthread_mutex_destroy(&pthread_mutex[i]) != 0) {return -1;}
	}
	return return_value;
}