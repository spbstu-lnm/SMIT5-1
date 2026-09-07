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


constexpr auto MAX_DISKS_COUNT = (26);

// fs name most likely will fit in 8 wchars
constexpr auto MAX_FS_NAME_LENGTH = (8);


struct OSInfo {
	uint32_t dwMajorVersion = 0;
	uint32_t dwMinorVersion = 0;
	uint32_t dwBuildNumber = 0;
};

struct timeInfo {
	uint64_t unixTime = 0;
	uint64_t msSinceStartup = 0;
};

struct memoryInfo {
	uint64_t totalRamKB = 0;
	uint64_t freeRamBytes = 0;
};

struct diskInfo {
	wchar_t* fileSystemNames[MAX_DISKS_COUNT][MAX_FS_NAME_LENGTH] = { 0 };
	uint32_t* diskTypes[MAX_DISKS_COUNT] = { 0 };
};

// each ACE is a separate struct instance
// ACE query response is terminated with "END" packet
struct ACEInfo {
	PSID subjectSID = 0;
	wchar_t* subjectName[UNLEN] = { 0 };

	uint8_t ACEType = 0;
	uint8_t ACEFlags = 0;
	uint32_t accessMask = 0;
};

struct ownerInfo {
	PSID ownerSID = 0;
	wchar_t* ownerName[UNLEN] = { 0 };
};

enum class ReturnCode {
	Success,
	// TODO
	UnexpectedError
};

typedef NTSTATUS(WINAPI* PFN_RtlGetVersion)(POSVERSIONINFOW);
