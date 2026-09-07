/******************************************************************************

	SMIT5-1.cpp: console application entry point --- SERVER

	|	Distributed PC info collection system, 
	|	employing sockets for communication.


	ARCHITECTURE:
		- system works in a local network
		
		- client (central PC) collects information about 
			remaining PCs in the network

		- info is collected automatically (by default)

		- server (daemon) provides information
			and is installed on all PCs in the network

		- on central PC client runs to request information

		* INFO COLLECTION IS INITIATED BY CLIENT (CENTRAL PC)
			client only requests info when it is able to accept it

		* SERVERS ARE ALWAYS READY TO ACCEPT CLIENT'S REQUEST
			when client is ready to receive info 
			and sends a request --- servers respond
		
		* SERVER IS STATELESS
			stateless servers are easier to maintain and more fault tolerant

	
	COLLECTED INFO:
		- Type and version of OS

		- Current time
		
		- Time passed from OS startup
		
		- memory info (total + free) 
		
		- types of connected disks (local/network/removable) + file system
		
		- free space on local disks
		
		- access rights (as a string) to a specified file / folder / reg key

		- owner of a file / folder / reg key

	
	GENERAL REQUIREMENTS:
		- must use sockets (WinSock, not wrappers from MFC libs or similar)
		
		- must implement separate query (request) for each type of info

		- replies must be suitable for automated processing, 
			not only human-readable


	SERVER REQUIREMENTS:
		- must work on Windows 7/8/10 (all SPs)

		- must be a non-interactive console application (daemon)

		- must output logs to console 
			* connection/disconnection of clients
			* received and processed queries\

		- must use Win32 IO Completion Ports for parallel query handling


	ENCRYPTION REQUIREMENTS:
		- must encrypt all messages between client and server with CryptoAPI

		- must use one of symmetric encryption algorithms with session key 
			to send data

		- must use one of assymetric encryption algorithms 
			to set up session key


	ENCRYPTION STACK:
		- Symmetric: AES-GCM
			BCRYPT_AES_ALGORITHM + BCRYPT_CHAIN_MODE_GCM
			256-bit key

		- Assymetric: ECDH (Elliptic Curve Diffie-Hellman)
			BCRYPT_ECDH_P384_ALGORITHM


	NOTES:
		- bcrypt.h used for data protection instead of deprecated crypt32.h

		- IO Completion Ports used to handle many users at once

******************************************************************************/


#include "SMIT5-1.h"


// CONSTANTS	===============================================================
// TODO


// GLOBALS	===================================================================
// TODO


// FUNCTIONS	===============================================================
// TODO


int main(void)
{
	return EXIT_SUCCESS;
}
