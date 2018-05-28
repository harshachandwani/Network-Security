#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/opensslconf.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <time.h>

#define ENCRYPT 1
#define DECRYPT 2

char* get_key(char* keyfile);
void proxy_side(int lport, int dport,struct hostent * dest_host, char* key);
void client_side(int dport, struct hostent* dest_host, char* key);
int encr_or_decr(char* msg, int n, int fd, AES_KEY *key, int operation );
void reint_proxy(int client_sock, int sock_proxy, int len, struct hostent* dhost,int dport);

struct ctr_state {
    unsigned char ivec[16];
    unsigned int  num;
    unsigned char ecount[16];
};

int main(int argc, char*argv[]){
	int lport = -1, dport = -1;
	int mode = 0, c = 0;
	char* keyfile = NULL;
	char* dest_host = NULL;
	char* key = NULL;
	
	while((c = getopt(argc, argv, "k:l:")) != -1){
		switch(c){
			case 'k':
				keyfile = optarg;
				key = get_key(keyfile);	
				if(!key){
					printf("No key found\n");
				}
				break;
			case 'l':
				lport = atoi(optarg);
				mode = 1;
				break;
			case '?':
				printf("Missing argument\n");
				break;
			default:
				break;
		}
	}	
	
	dest_host = argv[optind];
	dport = atoi(argv[optind + 1]);

	struct hostent* dhost = NULL;
	dhost = gethostbyname(dest_host);
	/* We differentiate between the client and the server based on the presence of -l option */
	if(mode){
		proxy_side(lport, dport, dhost, key);
	}
	else{
		client_side(dport, dhost, key);
	}
	return 0;	
}	

char* get_key(char* keyfile){
	char* key = NULL;
	int size = 0;
	FILE* fd = NULL;
	fd = fopen(keyfile, "r ");
	if(fd == NULL){
		printf("fopen failed\n");
		return NULL;
	}
	fseek(fd, 0, SEEK_END);
	size = ftell(fd);
    fseek(fd,0,SEEK_SET);

	key = malloc(size);
	if(!fread(key, 1, size, fd)){
		printf("read error!\n"); 
			return NULL;
	}
	fclose(fd);	
	return key;
}	

int init_ctr(struct ctr_state *state, const unsigned char iv[8])
{
	/* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
		* first call. */
	state->num = 0;
	memset(state->ecount, 0, 16);
	/* Initialise counter in 'ivec' to 0 */
	memset(state->ivec + 8, 0, 8);
	/* Copy IV into 'ivec' */
	memcpy(state->ivec, iv, 8);
	return(0);
}

int encr_or_decr(char* msg, int n, int fd, AES_KEY *key, int operation){
	if(operation == ENCRYPT){
		struct ctr_state state;
		unsigned char iv[8];
		unsigned char encr_msg[n];
		memset(encr_msg,0,n);

		if(!RAND_bytes(iv, 8)){
			puts("\nError in RAND_Bytes...\n");
			return -1;
		}	
		char* send_msg = (char*) malloc(n + 8);
		memcpy(send_msg, iv, 8);
		init_ctr(&state, iv);
		AES_ctr128_encrypt(msg, encr_msg, n, key, state.ivec, state.ecount, &state.num);
		memcpy(send_msg + 8,  encr_msg, n);
		write(fd, send_msg, n+8);
		free(send_msg);	
	}
	if(operation == DECRYPT){
	 	char *ptr=msg;
       	struct ctr_state state;
       	unsigned char iv[8];
       	unsigned char decr_msg[n-8];
        memset(decr_msg,0,n-8);

	    memcpy(iv, msg, 8);
        init_ctr(&state, iv);

	    AES_ctr128_encrypt(ptr+8, decr_msg, n - 8, key, state.ivec, state.ecount, &state.num);
       	write(fd, decr_msg, n-8);
	}
	return 0;
}	

void client_side(int dport, struct hostent * dhost, char *key){
	struct sockaddr_in pserver;
	int client_sock = -1;
	int n = 0;

	char msg[4096];
	memset(msg,0,4096);
	client_sock = socket(AF_INET, SOCK_STREAM, 0);
	if (client_sock == -1)
    {
        printf("Could not create socket");
        return ;
    }

	//dhost = gethostbyname(dest_host);
	bzero((char *) &pserver, sizeof(pserver));
	pserver.sin_addr.s_addr = ((struct in_addr *)(dhost->h_addr))->s_addr;
    pserver.sin_family = AF_INET;
    pserver.sin_port = htons(dport);
	
	 //Connect to remote server
    if (connect(client_sock, (struct sockaddr *)&pserver, sizeof(pserver)) < 0)
	{
        perror("Connection between client and proxy server failed\n");
        return;
    }	
	puts("Connection between client and proxy server established\n");
	fcntl(client_sock, F_SETFL, O_NONBLOCK);
	AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);
	
	fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
	
	while(1){
		while((n = read(STDIN_FILENO, msg, 4096)) >= 0){
        	if(n == 0){
            	fprintf(stderr, "Client Exiting!\n");
             	return;
            }
            if(n > 0){
            	encr_or_decr(msg, n, client_sock, &aes_key, ENCRYPT);
               	memset(msg,0,4096);
            }

		}

		while((n = read(client_sock, msg, 4096)) >= 0){
			if(n == 0){		
				fprintf(stderr, "Client Exiting!\n");
                return;
			}

			if (n > 0){
                encr_or_decr(msg, n, STDOUT_FILENO, &aes_key, DECRYPT);
                memset(msg,0,4096);
            }

		}
	}//while(1) ends here
}//client_side ends here

void proxy_side(int lport, int dport, struct hostent* dhost, char* key){
	unsigned char msg[4096];
	memset(msg,0,4096);
	
	int sock_server = 0, sock_proxy = 0, n = 0, client_sock = 0;
	int len = 0;
	struct sockaddr_in pserver, dserver;

	AES_KEY aes_key;

	sock_proxy = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_proxy == -1)
    {
    	printf("Could not create Proxy socket");
    }

    puts("Proxy Socket created");
    bzero((char *) &pserver, sizeof(pserver));
	pserver.sin_addr.s_addr = INADDR_ANY;
    pserver.sin_family = AF_INET;
    pserver.sin_port = htons(lport);
		
	if(bind(sock_proxy,(struct sockaddr *)&pserver , sizeof(pserver)) < 0)
    {
        perror("bind failed. Error");
        return;
    }
    puts("Proxy bind done\n");

    if(listen(sock_proxy , 3) < 0)
	{
		perror("Listen failed. Error");
        return;
    }

	struct sockaddr_in client;
	len = sizeof(pserver);
	client_sock = accept(sock_proxy, (struct sockaddr *)&client, (socklen_t*)&len);
	if (client_sock < 0)
    {
        perror("accept failed");
        return;
	}
	sock_server = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_server == -1)
    {
        printf("Could not create Server socket");
    }

    bzero((char *) &dserver, sizeof(dserver));
    dserver.sin_addr.s_addr = ((struct in_addr *)(dhost->h_addr))->s_addr;
    dserver.sin_family = AF_INET;
    dserver.sin_port = htons(dport);	
	
	if (connect(sock_server , (struct sockaddr *)&dserver , sizeof(dserver)) < 0)
    {
        perror("connect failed. Error");
        return;
    }
	puts("Connection between proxy and dest server established\n");
	fcntl(client_sock, F_SETFL, O_NONBLOCK);
	fcntl(sock_server, F_SETFL, O_NONBLOCK);
	AES_set_encrypt_key(key, 128, &aes_key);
    memset(msg, 0, sizeof(msg));

	while(1){
		while((n = read(client_sock, msg, 4096)) >= 0){	
			if(n <= 0){
				close(client_sock);
				close(sock_server);
				fprintf(stderr, "Proxy Server says - Client exiting\n");
 				reint_proxy(client_sock, sock_proxy, len, dhost, dport);
				break;
			}				
			if(n > 0){
				/* Decrypt the message and send it to the dserver i.e ssh server */
				encr_or_decr(msg, n, sock_server, &aes_key, DECRYPT);
				memset(msg,0,4096);
			}
		}
		
		/* message received from ssh server to proxy	server */
		while((n = read(sock_server, msg, 4096)) >= 0 ){	
			if(n <= 0){
				close(client_sock);
				close(sock_server);
				fprintf(stderr, "Proxy Server says -Server exiting\n");
			}
			if (n > 0){
				/* Encrypt the message from server and send it to the client */
            	encr_or_decr(msg, n, client_sock, &aes_key, ENCRYPT);
              	memset(msg,0,4096);
           	}
		}	
	}
}

void reint_proxy(int client_sock, int sock_proxy, int len, struct hostent* dhost, int dport){
			struct sockaddr_in client, dserver;
			client_sock = accept(sock_proxy, (struct sockaddr *)&client, (socklen_t*)&len);
			if (client_sock < 0){
	            perror("accept failed");
	            return;
	        }
			puts("Server: Connection between client and proxy server established\n");
			
			int sock_server = 0;	
			sock_server = socket(AF_INET, SOCK_STREAM, 0);
			if (sock_server == -1){
	            printf("Could not create Server socket");
	            return;
	        }
	        fcntl(client_sock, F_SETFL, O_NONBLOCK);
	       	bzero((char *) &dserver, sizeof(dserver));
			dserver.sin_addr.s_addr = ((struct in_addr *)(dhost->h_addr))->s_addr;
	        dserver.sin_family = AF_INET;
	       	dserver.sin_port = htons(dport);

			if (connect(sock_server , (struct sockaddr *)&dserver , sizeof(dserver)) < 0){
	        	perror("connect failed. Error");
	        	return;
	    	}			
			puts("Connection between proxy and dest server established\n");
			fcntl(sock_server, F_SETFL, O_NONBLOCK);
}
