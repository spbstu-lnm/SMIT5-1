/******************************************************************************
	
	SMIT5-1.h : include file

	NOTES:
		- NOMINMAX is used with Windows.h to avoid creation of min and max 
			macros

		- WS2tcpip.h was added for easier address conversion

		- bcrypt.h is used instead of deprecated crypt32.h

******************************************************************************/


#pragma once


#ifndef NOMINMAX	// ADDED
#define NOMINMAX
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif


#include <cstdio>	// REPLACED
#include <cstdlib>	// ADDED

#include <Windows.h>
#include <WinSock2.h>
#include <MSWSock.h>
#include <WS2tcpip.h>	// ADDED

#include <bcrypt.h>	// ADDED


#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")
#pragma comment(lib, "bcrypt.lib")	// ADDED
