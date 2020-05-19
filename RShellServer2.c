/*
 *   RShellServer1.c	example program for CS 468
 */


// OpenSSL Imports
#include <openssl/sha.h>
#include <time.h>
#include <stdbool.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdlib.h>

// Other Imports
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
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

// Password size (in Hex)--> 20 bytes, 2 chars rep 1 byte, so 40 chars
#define PASSWDSIZE 40

// Max ID size: 16 - 1 = 15 bytes for id, 1 for null term
#define IDSIZE 16

// Max length of payload (2^16) = 65536
#define MAXPLSIZE 65536

// Max potential message size (2^1) + (2^2) + (2^16)
#define MAXMSGSIZE 65542

// Command size- sub
#define MAXBUFSIZE ((MAXPLSIZE - IDSIZE) - 1)

// provided code definitions
#define LINELEN     (MAXBUFSIZE - 20)
#define BUFSZ       (MAXBUFSIZE - 20)
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
serversock(int UDPorTCP, int portN, int qlen)
{
    struct sockaddr_in svr_addr;    /* my server endpoint address       */
    int    sock;            /* socket descriptor to be allocated    */

    if (portN<0 || portN>65535 || qlen<0)   /* sanity test of parameters */
        return -2;

    bzero((char *)&svr_addr, sizeof(svr_addr));
    svr_addr.sin_family = AF_INET;
    svr_addr.sin_addr.s_addr = INADDR_ANY;

    /* Set destination port number */
    svr_addr.sin_port = htons(portN);

    /* Allocate a socket */
    sock = socket(PF_INET, UDPorTCP, 0);
    if (sock < 0)
        return -3;

    /* Bind the socket */
    if (bind(sock, (struct sockaddr *)&svr_addr, sizeof(svr_addr)) < 0)
        return -4;

    if (UDPorTCP == SOCK_STREAM && listen(sock, qlen) < 0)
        return -5;

    return sock;
}

inline int serverTCPsock(int portN, int qlen)
{
  return serversock(SOCK_STREAM, portN, qlen);
}

inline int serverUDPsock(int portN)
{
  return serversock(SOCK_DGRAM, portN, 0);
}

void usage(char *self)
{
    // Useage message when bad # of arguments
    fprintf(stderr, "Usage: %s <port to run server on> <password file> \n", self);
    exit(1);
}

void errmesg(char *msg)
{
    fprintf(stderr, "**** %s\n", msg);
    exit(1);

}

/*------------------------------------------------------------------------
 * reaper - clean up zombie children
 *------------------------------------------------------------------------
 */
void
reaper(int signum)
{
/*
    union wait  status;
*/

    int status;

    while (wait3(&status, WNOHANG, (struct rusage *)0) >= 0)
        /* empty */;
}

/*------------------------------------------------------------------------
 *  This is a very simplified remote shell, there are some shell command it
    can not handle properly:

    cd
 *------------------------------------------------------------------------
 */
int
RemoteShellD(int sock)
{
    char cmd[BUFSZ+20];
    char result[resultSz];
    int cc, len;
    int rc=0;
    FILE *fp;


    printf("***** RemoteShellD(sock=%d) called\n", sock);


    while ((cc = read(sock, cmd, BUFSZ)) > 0)   /* received something */
    {

        if (cmd[cc-1]=='\n')
            cmd[cc-1]=0;
        else cmd[cc] = 0;


        printf("***** RemoteShellD(%d): received %d bytes: `%s`\n", sock, cc, cmd);


        strcat(cmd, " 2>&1");

    printf("***** cmd: `%s`\n", cmd);

        if ((fp=popen(cmd, "r"))==NULL) /* stream open failed */
            return -1;

        /* stream open successful */

        while ((fgets(result, resultSz, fp)) != NULL)   /* got execution result */
        {
            len = strlen(result);
            printf("***** sending %d bytes result to client: \n`%s` \n", len, result);

            if (write(sock, result, len) < 0)
            { rc=-1;
              break;
            }
        }
        fclose(fp);

    }

    if (cc < 0)
        return -1;

    return rc;
}

// Modified Remote Shell method, builds message for remote shell command
Message * MsgRemoteShell(char *command, char *id){
    char result[resultSz];
    FILE *fp;

    memset(result, 0, resultSz);

    Message *msg = (Message*)(malloc(sizeof(Message)));

    if ((fp = popen(command, "r")) == NULL){
        /* stream open failed */
        return NULL;
    }

    printf("");

    // Combine stderr and stdout in command
    strcat(command, " 2>&1");

    // read result of execution
    fread(result, resultSz, 1, fp); 

    // close file
    pclose(fp);

    // null term result
    result[strlen(result) - 1] = '\0';

    unsigned char *iv = (unsigned char *)"0123456789012345";
    unsigned char *key = (unsigned char *)"a68d1818922322ebbac5272b1b8013962e092a76";
    unsigned char ciphertext[128];
    int ciphertext_len;
    ciphertext_len = encrypt(result, strlen ((char *)result), key, iv,ciphertext);
    // Set message type
    msg->msgtype = RSHELL_RESULT;
    // Set payload length 16 for id
    msg->paylen = IDSIZE + ciphertext_len;
    // Set 16 byte id, 15 bytes for user ID max
    memcpy(msg->id,id,(IDSIZE - 1));
    // Ensure the user ID is null-terminated
    msg->id[strlen(id)] = '\0';
    ciphertext[ciphertext_len] = '\0';
    msg->payload = ciphertext;

    printf("The result from command '%s' was:\n%s\n\n", command, result);

    return msg;
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
    if(msg->paylen > IDSIZE + 1){
        if ( (n = write(sock, msg->payload, (msg->paylen - IDSIZE) )) != (msg->paylen - IDSIZE) ){
            printf("ERROR: Has %d byte send when trying to send %d bytes for Message UserID: `%s`\n", n, (msg->paylen - IDSIZE), &msg);
            close(sock);
            return -1;
        }
    }

    return 0;
}



// Reads message from socket, returns NULL if there is an error during read
Message * read_message(int sock){
    // Create pointer to hold in the message read-in
    Message *msg = (Message*)(malloc(sizeof(Message)));

    // Read the message type
    if (read(sock, &msg->msgtype, TYPESIZE) != TYPESIZE){
        // Return NULL if there is an error
        // printf("ERROR: Could not read message type.\n");
        // Will reach here when client disconects.
        printf("Client has disconnected from the Server.\n"); 

        // Free memory
        free(msg);
        // Return NULL b/c of error
        return NULL;
    }

    // Read the message length
    if (read(sock, &msg->paylen, LENSIZE) != LENSIZE){
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
        if ( (read(sock, &msg->id, IDSIZE)) != IDSIZE ){
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
        if ( (read(sock, msg->payload, (msg->paylen - IDSIZE) )) != (msg->paylen - IDSIZE) ){
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



/*-------------------------------------------------------------------------------
 * Method to Authenticate sent client information with user/pass in password file
 *------------------------------------------------------------------------------*/

// Simple function for authentication
// Takes Client username, SHA1 hashed client password and compares to
// Server username and server SHA1 hashed password (read in from password file)
bool authenticate (char cluser[], char *pwdfname){

    // Username stored on the server read from the passwdfile.txt
    char *seruser;
    // SHA1 hashed password stored on the server read from the passwdfile.txt
  //  unsigned char *serpass;

    // user string with client user length
    char svruser[sizeof(cluser)];
    // hashed password string with client pass length
   // char svrpass[sizeof(clpass)];

    // Open and read the password file

    // Contains the format: <Username>; <hex representation of SHA1(PW)>
    // Example if the User was "Alice" and the password was "SecretPW":
    //      Alice; 0c8f72ea98dc74c71f9ff5bb72941036ae5120d9

    // Will parse the first line of the password file for the username and SHA1 password hash
    // Will first read line for username until finds the ";" symbol
    // Then after the ";" symbol will ignore whitespace and save the SHA1 hash in "hashedpass"

    // The password file
    FILE *passwdfile;

    // initialize line to null
    char *line = NULL;

    // Input / Output primatives
    // Length of line read
    size_t linelen = 0;
    // to read line from file
    ssize_t read;

    // Open the password file
    passwdfile = fopen(pwdfname, "r");

    // Check if the password file could be opened
    if (passwdfile == 0){
        // Not found or could not open
        printf("The specified password file was not found or could not be opened.\n");
        // Exit the program
        exit(1);
    }else{
        // The file could be opened, so read its contents
        // The file should only have 1 line in it (as defined in the spec)
        read = getline(&line, &linelen, passwdfile);

        // Close the password file when done
        fclose(passwdfile);

        // Parse the line for the username and SHA1 hash of the password
        char* linebuf;

        // Split on ";" symbol, get username
        linebuf = strtok(line, ";");
        // Copy into username
        memcpy(&seruser, &linebuf, sizeof(seruser));

        // Split on ";" symbol, get password
       // linebuf = strtok(NULL, ";");
        // Trim lead whitespace before the SHA1 password hash
       // while(isspace(*linebuf)){
         //   linebuf++;
      //  }
        // Get rid of the ending newline character from SHA1 hash
       // linebuf = strtok(linebuf, "\n");

        // Copy into hashedpass
       // memcpy(&serpass, &linebuf, sizeof(serpass));

        // Now the username and SHA1 hashed pass have been read from the password file
        // and stored into memory

        // Test print statements to see if username and password were read correctly from file
        //printf("Password file Username: \"%s\"\n", seruser);
        //printf("Password file Password: \"%s\"\n", serpass);

        // Test Client username and password
        //printf("Client Username: \"%s\"\n", cluser);
        //printf("Client Password: \"%s\"\n", clpass);

        // Check if usernames match
        if(strcmp(cluser, seruser) == 0){

            // The IDs are a match, so check if the hashed passwords match
           // if(strcmp(clpass, serpass) == 0){
                // The passwords match! So this is an AUTH_SUCESS
                printf("Authentication success!\n\n");
                // Free the line
                free(line);
                return true;
           // }else{
                // Hashed password did not match
             //   printf("Password did not match.\n\n");
           // }
        }else{
            // Username did not match
            printf("Invalid ID: %s\n\n", cluser);
        }
    }
    // Free the line
    free(line);
    // Username or password did not match, so this is an AUTH_FAIL
    return false;
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
 *      * Initialise the encryption operation. IMPORTANT - ensure you use a key
 *           * and IV size appropriate for your cipher
 *                * In this example we are using 256 bit AES (i.e. a 256 bit key). The
 *                     * IV size for *most* modes is the same as the block size. For AES this
 *                          * is 128 bits
 *                               */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
 *      * Provide the message to be encrypted, and obtain the encrypted output.
 *           * EVP_EncryptUpdate can be called multiple times if necessary
 *                */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
 *      * Finalise the encryption. Further ciphertext bytes may be written at
 *           * this stage.
 *                */
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
 * main - Concurrent TCP server
 *------------------------------------------------------------------------
 */
int
main(int argc, char *argv[])
{
    // Auth vars
    // server password file name (passed as a command line argument)
    char *passfname;

    // Command that the user wants to run on the RShell
    char *rshellcmd;

    // The message pointer
    Message *msg;

    // The user ID.
    char id[IDSIZE];


    // Variable that is true when the user is authenticated (successful login) or false if otherwise
    // After 60 seconds of authentication, should revert back to false
    bool auth = false;
    // Epoch times for calculatings 60 seconds past auth
    // Time of authentication
    struct timeval authtime;
    // Time of request for command
    struct timeval reqtime;

    // Can set and compare times with:
    /*
    gettimeofday(&authtime,NULL);
    gettimeofday(&reqtime,NULL);
    printf("SECONDS:%d\n", authtime.tv_sec);
    printf("SECONDS:%d\n", reqtime.tv_sec);
    */

    // Credentials sent by the client
    // Mock credentials sent by the client
    //char userid[] = "Alice"
    unsigned char mockpw[] = "0c8f72ea98dc74c71f9ff5bb72941036ae5120d9";

    //Var to hold hashed password from client
    unsigned char *password;
    unsigned char decryptedtext [128];
    unsigned char ciphertext [128];
    char * ptr;

    // Server Vars
    int  msock;         /* master server socket     */
    int  ssock;         /* slave server socket      */
    int  portN;         /* port number to listen */
    struct sockaddr_in fromAddr;    /* the from address of a client */
    unsigned int  fromAddrLen;      /* from-address length          */
    int  prefixL, r;

char strnonce1[50];
char * ptr2;
	long nonce1;
	long nonce2 = 64;
	long decnonce2;
char strnonce2[50];
sprintf(strnonce2,"%ld",nonce2);

    // check for 3 args: program name and then: port num, password file
    if (argc == 3){
        // Set port number to run server on
        portN = atoi(argv[1]);
        // Set filename for password for to be used 
        passfname = argv[2];
    }else{
        // Show proper format
        usage(argv[0]);
    }

    msock = serverTCPsock(portN, 5);

    (void) signal(SIGCHLD, reaper);

    while (1) {
        fromAddrLen = sizeof(fromAddr);
        ssock = accept(msock, (struct sockaddr *)&fromAddr, &fromAddrLen);
	if (ssock < 0) {
            if (errno == EINTR)
                continue;
            errmesg("accept error\n");
        }

        switch (fork())
        {
            case 0:     /* child */
                close(msock);

                // Print new connection message
                printf("Client has connected to the Server.\n"); 

                // Listen for client message 
               
		 while(msg = read_message(ssock)){
                    if(msg != NULL){
                        printf("Received Message from Client:\n");
                        print_message(msg);

                        gettimeofday(&reqtime,NULL);
                        // Set auth to false if have been authenticated for more than 60 seconds
                        // (Check time of requestion - time of authentication) > 60 seconds
                        if( (reqtime.tv_sec - authtime.tv_sec) > 60){
                            printf("More than 60 seconds have passed, setting user authentication to false.\n\n");
                            // Set auth to false
                            auth = false;
                        }

                        if(!auth){

                            // User hasn't been authenticated yet
                            switch(msg -> msgtype){
                                case RSHELL_REQ :
                                    // Save the nonce1
                                   // strnonce1  = (char*)malloc( (msg->paylen - IDSIZE) * sizeof(char));
                                    //memcpy(strnonce1, msg->payload, strlen(msg->payload));
                                    strcpy(strnonce1,msg->payload);
                                    // Ensure null terminated command
                                    strnonce1[(msg->paylen - IDSIZE) ] = '\0';
             
                                    printf("Client sent nonce1: %s\n\n", strnonce1);
                                    
                                    // Copy the from the message into the server id field
                                    memcpy(id,msg->id,IDSIZE);
                                    // Ensure the user ID is null-terminated
                                    id[strlen(id)] = '\0';
                                    //printf("THE ID FROM THE CLIENT IS: %s\n", id);
                                    // Free the current message
                                    free(msg);

                                    // Create a an AUTH_REQ message
                                    msg = malloc(sizeof(Message));
                                    // Set message type
                                    msg->msgtype = AUTH_REQ;
                                    // Set payload length 16 for id
                                    msg->paylen = IDSIZE + 4;
                                    // Set 16 byte id, 15 bytes for user ID max
                                    memcpy(msg->id,id,(IDSIZE - 1));
                                    // Ensure the user ID is null-terminated
                                    msg->id[strlen(id)] = '\0';
                                    // send nonce 2
                                    msg->payload = strnonce2;

                                    // Write the AUTH REQ MESSAGE
                                    printf("Sending the following Message from Server to Client:\n");
                                    print_message(msg);
                                    write_message(ssock, msg);
                                    break;
                                case AUTH_RESP :
                                    //ciphertext = (char*)malloc((msg->paylen - IDSIZE) * sizeof(char));
                                    //memcpy(ciphertext, msg->payload, strlen(msg->payload));
                                    strcpy(ciphertext,msg->payload);
				    unsigned char *iv = (unsigned char *)"0123456789012345";
                		    unsigned char *key = (unsigned char *)"a68d1818922322ebbac5272b1b8013962e092a76";
                        	    int decryptedtext_len;
				    decryptedtext_len = decrypt(ciphertext, strlen(msg->payload), key, iv, decryptedtext);
				    decryptedtext[decryptedtext_len] = '\0';
				    printf("Decrypted text is:\n");
				    printf("%s\n", decryptedtext);
				    decnonce2 = strtol(decryptedtext, &ptr, 10) - 1;
					//printf("decrypted nonce2 is %ld\n",decnonce2);
				    rshellcmd = (char*)malloc((strlen(decryptedtext) - strlen(strnonce2)) *  sizeof(char) + 1);
				    //memcpy(rshellcmd, decryptedtext, decryptedtext_len);
   				    //rshellcmd[decryptedtext_len ] = '\0';
   				    sprintf(rshellcmd,"%s",ptr);
				    rshellcmd[strlen(rshellcmd)] = '\0';
				    printf("The RShell command the user wants to run is: %s\n\n", rshellcmd);
   

                                    if(authenticate(id,passfname) && nonce2 == decnonce2){
                                        // Auth Success!!
                                       // free(password);
                                        // set auth to true

                                       // free(password);
                                        nonce1 = strtol(strnonce1, &ptr2, 10);
		                        nonce1 += 1;
                       		        sprintf(strnonce1,"%ld",nonce1);
                        		int ciphertext_len = encrypt(strnonce1, strlen ((char *)strnonce1), key, iv,ciphertext);
                        		//printf("Ciphertext is:\n");
					//BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);
                                        
					auth = true;
                                        // set time of authentication
                                        gettimeofday(&authtime,NULL);
                                        // Free the current message
                                        free(msg);

                                        // Create a an AUTH_SUC message
                                        msg = malloc(sizeof(Message));
                                        // Set message type
                                        msg->msgtype = AUTH_SUCCESS;
                                        // Set payload length 16 for id
                                        msg->paylen = IDSIZE + ciphertext_len + 1;
                                        // Set 16 byte id, 15 bytes for user ID max
                                        memcpy(msg->id,id,(IDSIZE - 1));
                                        // Ensure the user ID is null-terminated
                                        msg->id[strlen(id)] = '\0';
                                        // Don't need to set a payload for this message
                                        ciphertext[ciphertext_len] = '\0';
                                        msg->payload = ciphertext;

                                        // Write the AUTH SUCCESS
                                        printf("Sending the following Message from Server to Client:\n");
                                        print_message(msg);
                                        write_message(ssock, msg);
                                        // Now I actually have to run the command

                                        /*
                                        RUN COMMAND AND RETURN RESULT START
                                        */

                                        free(msg);

                                        printf("The RShell command to be run on the Server is: %s\n\n", rshellcmd);

                                        // Create a an RSHELL_RESULT message
                                        msg = MsgRemoteShell(rshellcmd, id);
		 
                                        // Write the RSHELL RESULT
                                        printf("Sending the following Message from Server to Client:\n");
                                        print_message(msg);
                                        write_message(ssock, msg);

                                        // Free the message
                                        free(msg);

                                        // Free rshellcmd
                                        free(rshellcmd);

                                        /*
                                        RUN COMMAND AND RETURN RESULT END
                                        */
                                        break;
                                    }else{
                                        // Auth fail
                                        //free(password);
                                        auth = false;

                                        // Free the current message
                                        free(msg);
                                        // Create a an AUTH_SUC message
                                        msg = malloc(sizeof(Message));
                                        // Set message type
                                        msg->msgtype = AUTH_FAIL;
                                        // Set payload length 16 for id
                                        msg->paylen = IDSIZE + strlen(strnonce1) + 1;
                                        // Set 16 byte id, 15 bytes for user ID max
                                        memcpy(msg->id,id,(IDSIZE - 1));
                                        // Ensure the user ID is null-terminated
                                        msg->id[strlen(id)] = '\0';
                                        // Don't need to set a payload for this message
                                        msg->payload = strnonce1;

                                        // Write the AUTH FAIL
                                        printf("Sending the following Message from Server to Client:\n");
                                        print_message(msg);
                                        write_message(ssock, msg);
                                    }
                                    break;
                                default :
                                    printf("ERROR: Received Invalid message.\n");
                                    break;
                            }
                        }else{
                            // The user has already been authenticated, just run command
                            printf("The user %s has already been authenticated. Will run command.\n\n", id);
                            switch(msg -> msgtype){
                                case RSHELL_REQ :
                                    // Save the command the user wants to run
                                    rshellcmd = (char*)malloc( (msg->paylen - IDSIZE) * sizeof(char));
                                    memcpy(rshellcmd, msg->payload, strlen(msg->payload));
                                    // Ensure null terminated command
                                    rshellcmd[(msg->paylen - IDSIZE) ] = '\0';
                                    
                                    // Copy the from the message into the server id field
                                    memcpy(id,msg->id,IDSIZE);
                                    // Ensure the user ID is null-terminated
                                    id[strlen(id)] = '\0';
                                    printf("THE ID FROM THE CLIENT IS: %s\n", id);
                                    // Free the current message
                                    free(msg);

                                    /*
                                    RUN COMMAND AND RETURN RESULT START
                                    */

                                    printf("The RShell command to be run on the Server is: %s\n\n", rshellcmd);

                                    // Create a an RSHELL_RESULT message
                                    msg = MsgRemoteShell(rshellcmd, id);

                                    // Write the RSHELL RESULT
                                    printf("Sending the following Message from Server to Client:\n");
                                    print_message(msg);
                                    write_message(ssock, msg);

                                    // Free the message
                                    free(msg);

                                    // Free rshellcmd
                                    free(rshellcmd);

                                    /*
                                    RUN COMMAND AND RETURN RESULT END
                                    */
                                    break;
                                default :
                                    printf("ERROR: Received Invalid message.\n");
                                    break;
                            }
                        }
                    }
                }
                close(ssock);
                exit(r);

            default:    /* parent */
                (void) close(ssock);
                break;
            case -1:
                errmesg("fork error\n");
        }
    }
    close(msock);
}
