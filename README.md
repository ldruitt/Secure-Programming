# Secure-Programming
Implementing a primitive authenticated remote shell client and server

-------------------------------------------------------------------------------
				URLS REFERENCED
-------------------------------------------------------------------------------

https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
https://www.openssl.org/docs/man1.1.0/man1/sha256.html
https://www.tutorialspoint.com/c_standard_library/c_function_strtol.htm

-------------------------------------------------------------------------------
				GENERATE EXECUTABLE
-------------------------------------------------------------------------------

gcc RShellServer2.c -o RShellServer2 -lcrypto
gcc RShellClient2.c -o RShellClient2 -lcrypto

-------------------------------------------------------------------------------
					NOTES
-------------------------------------------------------------------------------

To run: 

-make connection: RShellServer2	<port	num>	passwdfile.txt
	 	  RShellClient2	 localhost	<port	num>	Alice	SecretPW

-type command

-the response is given

-end connection
