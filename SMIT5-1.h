/******************************************************************************

	SMIT5-1.h : include file

	NOTES:
		- NOMINMAX is used with Windows.h to avoid creation of min and max
			macros

		- WS2tcpip.h was added for easier address conversion

		- bcrypt.h is used instead of deprecated crypt32.h

		- cross-platform std::chrono::system_clock used to get unixTime
			GetTickCount64() still used as more reliable way to get uptime

		- RtlGetVersion from "ntdll.dll" used
			instead of deprecated GetVersionEx()

		- GlobalMemoryStatusEx() used instead of
			deprecated GlobalMemoryStatus()

		- GetPhysicallyInstalledSystemMemory() used in addition
			to GlobalMemoryStatusEx() to get precise amt of RAM

		- GetDriveTypeW() used instead of deprecated function

		- cross-platform std::filesystem::space
		used instead of GetDiskFreeSpaceExW()

******************************************************************************/


#pragma once


// NOMINMAX and WIN32_LEAN_AND_MEAN moved to CMakeLists.txt


#include <cstdio>		// REPLACED
#include <cstdlib>		// ADDED
#include <cstdint>		// ADDED
#include <expected>		// ADDED
#include <print>		// ADDED
#include <format>		// ADDED for server logging (std::format)
#include <memory>		// ADDED
#include <utility>		// ADDED
#include <string>		// ADDED

#include <iostream>		// ADDED for wcout + format

#include <chrono>		// ADDED
#include <filesystem>	// ADDED

// WinSock2 must be included before other WinAPI headers
#include <WinSock2.h>
#include <Windows.h>
#include <MSWSock.h>
#include <WS2tcpip.h>	// ADDED

#include <AclAPI.h>		// ADDED
#include <lmcons.h>		// ADDED

#include <bcrypt.h>		// ADDED


#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")
#pragma comment(lib, "bcrypt.lib")	// ADDED


using PFN_RtlGetVersion = NTSTATUS(WINAPI*)(POSVERSIONINFOW);
