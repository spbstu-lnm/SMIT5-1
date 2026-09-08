/******************************************************************************
	
	SMIT5-1.h : include file

	NOTES:
		- NOMINMAX is used with Windows.h to avoid creation of min and max 
			macros

		- WS2tcpip.h was added for easier address conversion

		- bcrypt.h is used instead of deprecated crypt32.h

		- cross-platform chrono::system_clock used to get unixTime
			GetTickCount64() still used as more reliable way to get uptime

		- RtlGetVersion from "ntdll.dll" used 
			instead of deprecated GetVersionEx()

		- GlobalMemoryStatusEx() used instead of 
			deprecated GlobalMemoryStatus()

		- GetPhysicallyInstalledSystemMemory() used in addition 
			to GlobalMemoryStatusEx() to get precise amt of RAM

		- GetDriveTypeW() and GetDiskFreeSpaceExW() used 
			instead of deprecated functions

******************************************************************************/


#pragma once


// NOMINMAX and WIN32_LEAN_AND_MEAN moved to CMakeLists.txt


#include <cstdio>	// REPLACED
#include <cstdlib>	// ADDED
#include <expected>	// ADDED

#include <chrono>	// ADDED

#include <AclAPI.h> // ADDED
#include <lmcons.h>	// ADDED

#include <Windows.h>
#include <WinSock2.h>
#include <MSWSock.h>
#include <WS2tcpip.h>	// ADDED

#include <bcrypt.h>	// ADDED


#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")
#pragma comment(lib, "bcrypt.lib")	// ADDED


typedef NTSTATUS(WINAPI* PFN_RtlGetVersion)(POSVERSIONINFOW);
