/*  
 *   RShellClient1.c	example program for CS 468
 */


// OpenSSL Imports
#include <openssl/sha.h>
#include <time.h>
#include <stdbool.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>


// Other Imports
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/errno.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/errno.h>

// Definitions for message type
#define RSHELL_REQ 0x01
#define AUTH_REQ 0x02
#define AUTH_RESP 0x03
#define AUTH_SUCCESS 0x04
#define AUTH_FAIL 0x05
#define RSHELL_RESULT 0x06

// Size in bytes of Message type
#define TYPESIZE 1

 // Size in bytes of Message payload length
#define LENSIZE 2

// Max ID size: 16 - 1 = 15 bytes for id, 1 for null term
#define IDSIZE 16

// Password size (in Hex)--> 20 bytes, 2 chars rep 1 byte, so 40 chars
#define PASSWDSIZE 40

// Max length of payload (2^16) = 65536
#define MAXPLSIZE 65536

// Max potential message size (2^1) + (2^2) + (2^16)
#define MAXMSGSIZE 65542

// Command size
#define MAXBUFSIZE ((MAXPLSIZE - IDSIZE) - 1)

// provided code definitions
#define LINELEN     MAXBUFSIZE
#define BUFSZ       MAXBUFSIZE
#define resultSz    (MAXPLSIZE - 1)


// Typedef for the message format
typedef struct Message{
	// Message type
	char msgtype;
	// payload length in bytes
	short paylen;
	// id for the first 16 bytes of the payload
	char id[IDSIZE];
	// the payload
    char *payload;
}Message;


// Method to determine the message type.
int decode_type(Message *msg){
    switch(msg -> msgtype){
        case RSHELL_REQ :
            printf("Received RSHELL_REQ message.\n");
            return 1;
            break;
        case AUTH_REQ :
            printf("Received AUTH_REQ message.\n");
            return 2;
            break;
        case AUTH_RESP :
            printf("Received AUTH_RESP message.\n");
            return 3;
            break;
        case AUTH_SUCCESS :
            printf("Received AUTH_SUCCESS message.\n");
            return 4;
            break;
        case AUTH_FAIL :
            printf("Received AUTH_FAIL message.\n");
            return 5;
            break;
        case RSHELL_RESULT :
            printf("Received RSHELL_RESULT message.\n");
            return 6;
            break;
        default :
            printf("ERROR: Received Invalid message.\n");
            return -1;
            break;
    }
}

// Debug method to print a Message
void print_message(Message *msg){
	printf("MESSAGE--> TYPE:0x0%d   PAYLEN:%d  ID:%s   PAYLOAD:%s\n\n", msg->msgtype, msg->paylen, msg->id, msg->payload);
}

int
clientsock(int UDPorTCP, const char *destination, int portN)
{
	struct hostent	*phe;		/* pointer to host information entry	*/
	struct sockaddr_in dest_addr;	/* destination endpoint address		*/
	int    sock;			/* socket descriptor to be allocated	*/


	bzero((char *)&dest_addr, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;

    /* Set destination port number */
	dest_addr.sin_port = htons(portN);

    /* Map host name to IPv4 address, does not work well for IPv6 */
	if ( (phe = gethostbyname(destination)) != 0 )
		bcopy(phe->h_addr, (char *)&dest_addr.sin_addr, phe->h_length);
	else if (inet_aton(destination, &(dest_addr.sin_addr))==0) /* invalid destination address */
		return -2;

/* version that support IPv6
	else if (inet_pton(AF_INET, destination, &(dest_addr.sin_addr)) != 1)
*/

    /* Allocate a socket */
	sock = socket(PF_INET, UDPorTCP, 0);
	if (sock < 0)
		return -3;

    /* Connect the socket */
	if (connect(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
		return -4;

	return sock;
}

inline int clientTCPsock(const char *destination, int portN)
{
  return clientsock(SOCK_STREAM, destination, portN);
}


inline int clientUDPsock(const char *destination, int portN)
{
  return clientsock(SOCK_DGRAM, destination, portN);
}


void usage(char *self)
{
	// Useage message when bad # of arguments
	fprintf(stderr, "Usage: %s <server IP> <server port number> <ID> <password> \n", self);
	exit(1);
}

void errmesg(char *msg)
{
	fprintf(stderr, "**** %s\n", msg);
	exit(1);

}

/*------------------------------------------------------------------------------
 * TCPrecv - read TCP socket sock w/ flag for up to buflen bytes into buf

 * return:
	>=0: number of bytes read
	<0: error
 *------------------------------------------------------------------------------
 */
int
TCPrecv(int sock, char *buf, int buflen, int flag)
{
	int inbytes, n;

	if (buflen <= 0) return 0;

  /* first recv could be blocking */
	inbytes = 0;
	n=recv(sock, &buf[inbytes], buflen - inbytes, flag);
	if (n<=0 && n != EINTR)
		return n;

	buf[n] = 0;


	printf("\tTCPrecv(sock=%d, buflen=%d, flag=%d): first read %d bytes : `%s`\n",
			   sock, buflen, flag, n, buf);

  /* subsequent tries for for anything left available */

	for (inbytes += n; inbytes < buflen; inbytes += n)
	{
	 	if (recv(sock, &buf[inbytes], buflen - inbytes, MSG_PEEK|MSG_DONTWAIT)<=0) /* no more to recv */
			break;
	 	n=recv(sock, &buf[inbytes], buflen - inbytes, MSG_DONTWAIT);
		buf[n] = 0;


		printf("\tTCPrecv(sock=%d, buflen=%d, flag=%d): subsequent read %d bytes : `%s`\n",
			   sock, buflen, flag, n, &buf[inbytes]);


	  if (n<=0) /* no more bytes to receive */
		break;
	};


		printf("\tTCPrecv(sock=%d, buflen=%d): read totally %d bytes : `%s`\n",
			   sock, buflen, inbytes, buf);


	return inbytes;
}

int
RemoteShell(char *destination, int portN)
{
	char	buf[LINELEN+1];		/* buffer for one line of text	*/
	char	result[resultSz+1];
	int	sock;				/* socket descriptor, read count*/


	int	outchars, inchars;	/* characters sent and received	*/
	int n;

	if ((sock = clientTCPsock(destination, portN)) < 0)
		errmesg("fail to obtain TCP socket");

	while (fgets(buf, sizeof(buf), stdin))
	{
		buf[LINELEN] = '\0';	/* insure line null-terminated	*/
		outchars = strlen(buf);
		if ((n=write(sock, buf, outchars))!=outchars)	/* send error */
		{

			printf("RemoteShell(%s, %d): has %d byte send when trying to send %d bytes to RemoteShell: `%s`\n",
			   destination, portN, n, outchars, buf);

			close(sock);
			return -1;
		}

		printf("RemoteShell(%s, %d): sent %d bytes to RemoteShell: `%s`\n",
			   destination, portN, n, buf);


		/* Get the result */

		if ((inchars=recv(sock, result, resultSz, 0))>0) /* got some result */
		{
			result[inchars]=0;
			fputs(result, stdout);
		}
		if (inchars < 0)
				errmesg("socket read failed\n");
	}

	close(sock);
	return 0;
}

// Writes messages to socket: Returns 0 if successful, 1 if there was an error
int write_message(int sock, Message *msg){
    // Size will be the message type + paylen + ID + payload
    int msgsize = sizeof(char) + sizeof(short) + (sizeof(char) * msg->paylen);
    // n will store return value of write()
	int n;

    //printf("The size of the message you are sending is: %d\n", msgsize);

    // Write the message type
    if ( (n = write(sock, &msg->msgtype, TYPESIZE)) != TYPESIZE ){
        printf("ERROR: Has %d byte send when trying to send %d bytes for Message Type: `%s`\n", n, TYPESIZE, &msg);
        close(sock);
        return -1;
    }

    // Write the message length
    if ( (n = write(sock, &msg->paylen, LENSIZE)) != LENSIZE ){
        printf("ERROR: Has %d byte send when trying to send %d bytes for Message Length: `%s`\n", n, LENSIZE, &msg);
        close(sock);
        return -1;
    }

    // Write the user ID
    if(msg->paylen >= IDSIZE){
    	if ( (n = write(sock, &msg->id, IDSIZE)) != IDSIZE ){
        	printf("ERROR: Has %d byte send when trying to send %d bytes for Message UserID: `%s`\n", n, IDSIZE, &msg);
        	close(sock);
        	return -1;
    	}
    }

    // Write the payload, check IDSIZE + 1 for null term
    if(msg->paylen > IDSIZE){
    	if ( (n = write(sock, msg->payload, (msg->paylen - IDSIZE) )) != (msg->paylen - IDSIZE) ){
        	printf("ERROR: Has %d byte send when trying to send %d bytes for Message UserID: `%s`\n", n, (msg->paylen - IDSIZE), &msg);
        	close(sock);
        	return -1;
    	}
    }

	return 0;
}


// Recv message from socket, returns NULL if there is an error during read
Message * recv_message(int sock){
	// Create pointer to hold in the message read-in
	Message *msg = (Message*)(malloc(sizeof(Message)));

	// Read the message type
	if (recv(sock, &msg->msgtype, TYPESIZE, 0) != TYPESIZE){
		// Return NULL if there is an error
		printf("ERROR: Could not read message type.\n");
		// Free memory
		free(msg);
		// Return NULL b/c of error
		return NULL;
	}

	// Read the message length
	if (recv(sock, &msg->paylen, LENSIZE, 0) != LENSIZE){
		// Return NULL if there is an error
		printf("ERROR: Could not read message length.\n");
		// Free memory
		free(msg);
		// Return NULL b/c of error
		return NULL;
	}

    // Check if 16 bytes of ID exists
    if(msg->paylen >= IDSIZE){
    	// Write the user ID
    	if ( (recv(sock, &msg->id, IDSIZE, 0)) != IDSIZE ){
        	printf("ERROR: Could not read message ID.\n");
			// Free memory
			free(msg);
			// Return NULL b/c of error
			return NULL;
    	}
    }

    // Check if more 16 bytes of length exist, b/c first 16 is ID, the rest would be payload...
    if(msg->paylen > IDSIZE){
    	// Need to malloc new memory for the incoming payload
    	// The size is the payload size described in the message - the ID bytes
    	msg->payload = (char*)malloc( (msg->paylen - IDSIZE) * sizeof(char));
    	// Write the payload
    	if ( (recv(sock, msg->payload, (msg->paylen - IDSIZE), 0)) != (msg->paylen - IDSIZE) ){
        	printf("ERROR: Could not read message payload.\n");
        	// Free memory
			free(msg);
			// Return NULL b/c of error
			return NULL;
    	}
    }

    // Return pointer to read-in message
	return msg;
}


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
 ** Initialise the encryption operation. IMPORTANT - ensure you use a key
 ** and IV size appropriate for your cipher
 ** In this example we are using 256 bit AES (i.e. a 256 bit key). The
 ** IV size for *most* modes is the same as the block size. For AES this
 ** is 128 bits
 **/
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
 ** Provide the message to be encrypted, and obtain the encrypted output.
 ** EVP_EncryptUpdate can be called multiple times if necessary
 **/
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
 ** Finalise the encryption. Further ciphertext bytes may be written at
 ** this stage.
 **/
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
 *      * Initialise the decryption operation. IMPORTANT - ensure you use a key
 *           * and IV size appropriate for your cipher
 *                * In this example we are using 256 bit AES (i.e. a 256 bit key). The
 *                     * IV size for *most* modes is the same as the block size. For AES this
 *                          * is 128 bits
 *                               */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
 *      * Provide the message to be decrypted, and obtain the plaintext output.
 *           * EVP_DecryptUpdate can be called multiple times if necessary.
 *                */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
 *      * Finalise the decryption. Further plaintext bytes may be written at
 *           * this stage.
 *                */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

/*------------------------------------------------------------------------
 * main  *------------------------------------------------------------------------
 */
int
main(int argc, char *argv[])
{
    // Command line arg variables
	// This is the ip address to connect to, in this case, localhost
	char *destination;
	// The port number to connect to on the server
	int portN;
	// User id, ie "Alice"
	char *userid;
	// Will contain the final SHA1 hash of the user's password, needs *2 SHA digest len
	unsigned char password[SHA_DIGEST_LENGTH * 2];

	unsigned char key[SHA_DIGEST_LENGTH * 2];
	// String to temporarily hold the hash after the cipher is finalized
	unsigned char tmphash[SHA_DIGEST_LENGTH];
	unsigned char tmphash2[SHA_DIGEST_LENGTH];

	unsigned char ciphertext[128];
	unsigned char decryptedtext[128];
    // Space for command is the Payload size - 16 for user ID - 1 for null term
    char buf[MAXBUFSIZE + 1];
    // The user ID.
    char id[IDSIZE];
    // nonce 1
char strnonce1 [50];
        long nonce1 = 32;
        long nonce2;
	long decnonce1;
char strnonce2[50];
char * ptr;
sprintf(strnonce1,"%ld",nonce1);

    // For recv
    int inchars;
	Message *recvmsg;

	// Make sure 5 arguments-- The prog name and: <server IP> <server port number> <ID> <password>
	if (argc == 5){
		destination = argv[1];
		portN = atoi(argv[2]);
		userid = argv[3];
		// Instead of temporarily storing argv[4] in a temporary varaible
		// I decide to immediately hash it using SHA1 and store the hash in password[]

        // Using OpenSSL SHA functions for SHA1 hashing of the password

        // Create context for SHA1 hashing
        SHA_CTX ctx;

        // Initialize the SHA1 context
        SHA1_Init(&ctx);

        // Call update to hash the user's password with the password length
        SHA1_Update(&ctx, argv[4], strlen( argv[4] ));

        // Finalize the hash once I have the user's password
        SHA1_Final(tmphash, &ctx);


        // Counter for converting hash into bytes (%02x)-- Same concept as HWK2
        int hctr = 0;

        // Reformat properly -- 2 chars at a time for 1 byte each from temp hash into hash
        // After this loop, "hash" contains the properly formatted hash that
        // the OpenSSL function: "openssl sha1 -hex" would return
        for (hctr = 0; hctr < SHA_DIGEST_LENGTH; hctr++){
                sprintf( ((unsigned char*) &(password[ hctr * 2 ])), "%02x", tmphash[ hctr ] );
        }

        // Print the result of the hashed password
        printf("The password \"%s\" has a SHA1 hash of \"%s\".\n\n", argv[4], password);

        // print the 4 primary credentials:
        printf("Running Client with the following credentials...\n");
        printf("    Destination: %s\n    Port: %d\n    User_ID: %s\n    Hashed_Password: %s\n\n",destination,portN,userid,password);
	strcpy(key,password);
	strcat(key,strnonce1);
        // The password from argv[4] has now been hashed and saved in password[]

	}
	else {
		// Display usage information if wrong # of arguments
		usage(argv[0]);
	}

	// Create the socket
	int	sock;
	if ((sock = clientTCPsock(destination, portN)) < 0){
		errmesg("Failed to obtain TCP socket.");
		exit(1);
	}

	// Create message for command RSHELL_REQ
    Message *msg;

    // Clear the buffer
	buf[0] = '\0';


    printf("Connection established. Type a command to run on the Remote Shell...\n");
    // Get the shell command from the user
	while(fgets(buf, sizeof(buf), stdin)){
		// Check if buffer has anything
		if(strlen(buf) > 1){
			// Print newline after entered character
			printf("\n");
			// Ensure the buffer is null-terminated
		    buf[strlen(buf) - 1] = '\0';

		    // Create message for command RSHELL_REQ
		    msg = malloc(sizeof(Message));
		    // Set message type
		    msg->msgtype = 0x01;
		    // Set payload length 16 + 4 for nonce
		    msg->paylen = IDSIZE + 4;
		    // Set 16 byte id, 15 bytes for user ID max
		    memcpy(msg->id,userid,(IDSIZE - 1));
		    // Ensure the user ID is null-terminated
		    msg->id[strlen(userid)] = '\0';
		    // Set variable length Payload
		    msg->payload = strnonce1;


			// Send RShell Req 
			printf("Sending the following Message from Client to Server:\n");
		    print_message(msg);
			write_message(sock, msg);


			// Wait for AUTH_CHLG
			recvmsg = recv_message(sock);
			printf("Received Message from Server:\n");
			print_message(recvmsg);
			//strnonce2  = (char*)malloc( (recvmsg->paylen - IDSIZE) * sizeof(char));
                        //memcpy(strnonce2, recvmsg->payload, strlen(recvmsg->payload));
                        strcpy(strnonce2,recvmsg->payload);
                        // Ensure null terminated command
                        strnonce2[(msg->paylen - IDSIZE) ] = '\0';
			strcat(key,strnonce2);

   			SHA256_CTX sha256;
   			SHA256_Init(&sha256);
   			SHA256_Update(&sha256, key, strlen(key));
   			SHA256_Final(tmphash2, &sha256);
			int hctr2;
        		for (hctr2 = 0; hctr2 < SHA_DIGEST_LENGTH; hctr2++){
        		        sprintf( ((unsigned char*) &(key[ hctr2 * 2 ])), "%02x", tmphash2[ hctr2 ] );
        		}
                        printf("Server sent nonce2: %s\n\n", strnonce2);
			printf("Key is: %s\n", key);
			nonce2 = strtol(strnonce2, &ptr, 10);
			nonce2 += 1;
			sprintf(strnonce2,"%ld",nonce2);
			strcat(strnonce2,buf);
			unsigned char *iv = (unsigned char *)"0123456789012345";
			//unsigned char *key = (unsigned char *)"c7b9ef4efd429367e002e6a93c115e4d3b82967576ab795310a3c970a65c4ae4";
			int ciphertext_len;
			ciphertext_len = encrypt(strnonce2, strlen ((char *)strnonce2), key, iv,ciphertext);
			//printf("Ciphertext is:\n");
			//BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

			switch(recvmsg -> msgtype){
				case AUTH_REQ :
				  	// Create message for command AUTH_RESP
				  	free(msg);
				  	msg = malloc(sizeof(Message));
				    // Set message type
				    msg->msgtype = 0x03;
				    // Set payload length 16 + buffer + 1 for null terminator
				    msg->paylen = IDSIZE + ciphertext_len + 1;
				    // Set 16 byte id, 15 bytes for user ID max
				    memcpy(msg->id,userid,(IDSIZE - 1));
				    // Ensure the user ID is null-terminated
				    msg->id[strlen(userid)] = '\0';
				    // Esnure password is null-terminateor
				    
				    ciphertext[ciphertext_len] = '\0';
				    // Set variable length Payload
				    msg->payload = ciphertext;

				    // Free recvmsg
				    free(recvmsg);

				   	// Send AUTH_RESP
				   	printf("Sending the following Message from Client to Server:\n");
				   	print_message(msg);
					write_message(sock, msg);


					// Wait for AUTH_SUCCESS / AUTH_FAIL 
					recvmsg = recv_message(sock);
					printf("Received Message from Server:\n");
					int decryptedtext_len;
                                   	decryptedtext_len = decrypt(recvmsg->payload, strlen(recvmsg->payload), key, iv, decryptedtext);
                                   	decryptedtext[decryptedtext_len] = '\0';
                                    	//printf("Decrypted text is:\n");
                                    	//printf("%s\n", decryptedtext);
                                    	decnonce1 = strtol(decryptedtext, &ptr, 10) - 1;
                                        //printf("decrypted nonce1 is %ld\n",decnonce1);
					switch(recvmsg -> msgtype){
						case AUTH_SUCCESS :
						    // Free recvmsg
				    		free(recvmsg);
							if(decnonce1 == nonce1){
								printf("This response is valid!\n");
							}
							printf("Authentication Success!\n");

							// Get the command exec result
							recvmsg = recv_message(sock);
							printf("Received Message from Server:\n");
							if(recvmsg -> msgtype == RSHELL_RESULT){
								// Got the result
								// Print the result
								if(recvmsg->payload != NULL){
									strcpy(ciphertext,recvmsg->payload);
                                   					decryptedtext_len = decrypt(ciphertext, strlen(recvmsg->payload), key, iv, decryptedtext);
                                   					decryptedtext[decryptedtext_len] = '\0';
                                    					printf("\nThe result of the command was:\n");
                                    					printf("%s\n", decryptedtext);
								}else{
									// command not found
									printf("\nThe result of the command was:\ncommand not found\n\n");
								}
							}else{
								printf("ERROR: Received Invalid message.\n");
							}

							break;
						case AUTH_FAIL :
						    // Free recvmsg
				    		free(recvmsg);
							printf("Authentication Failed!\n");
							exit(1);
							break;
						default :
							printf("ERROR: Received Invalid message.\n");
							break;
					}
					break;

				case RSHELL_RESULT :
					// Print the result
					if(recvmsg->payload != NULL){
						strcpy(ciphertext,recvmsg->payload);
                                   		decryptedtext_len = decrypt(ciphertext, strlen(recvmsg->payload), key, iv, decryptedtext);
                                   		decryptedtext[decryptedtext_len] = '\0';
                                    		printf("\nThe result of the command was:\n");
                                    		printf("%s\n", decryptedtext);
					}else{
						// command not found
						printf("\nThe result of the command was:\ncommand not found\n\n");
					}
					break;
				default :
					printf("ERROR: Received Invalid message.\n");
					break;
			}
			// Clear the buffer
		    buf[0] = '\0';
		    // Print seperating stars
		    printf("**********************************************************************\n\n");
		    // Ask for another command
		    printf("Type another command to run on the Remote Shell...\n");
		}else{
			// Quit program
			exit(0);
		}
	}



	// Terminate the program 
	exit(0);
}
