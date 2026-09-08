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

	
	PROTOCOL:
		see structs in header file


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

		- Asymmetric: ECDH (Elliptic Curve Diffie-Hellman)
			BCRYPT_ECDH_P384_ALGORITHM


	NOTES:
		- bcrypt.h used for data protection instead of deprecated crypt32.h

		- IO Completion Ports used to handle many users at once

******************************************************************************/


#include "SMIT5-1.h"
#include "SharedStructs.h"


// CONSTANTS	===============================================================
// also see header file
// TODO


// GLOBALS	===================================================================
// TODO


// STRUCTS definition in header file


// PROTOTYPES	===============================================================
static std::expected<struct OSInfo, ReturnCode> gatherOSInfo(void);
static std::expected<struct systemTimeInfo, ReturnCode> gatherUnixTime(void);
static std::expected<struct uptimeInfo, ReturnCode> gatherUptime(void);
static std::expected<struct memoryInfo, ReturnCode> gatherMemoryInfo(void);

static ReturnCode localRun(void);

// FUNCTIONS	===============================================================
// ==== Gathering functions
static std::expected<struct OSInfo, ReturnCode> gatherOSInfo(void) {
	struct OSInfo osi;
	
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtdll) {
		printf("FAIL: Unable to get ntdll.dll\n");
		return std::unexpected(ReturnCode::UnexpectedError);
	}

	auto pRtlGetVersion = reinterpret_cast<PFN_RtlGetVersion>(
		GetProcAddress(hNtdll, "RtlGetVersion")
	);

	if (!pRtlGetVersion) {
		printf("FAIL: Couldn't resolve RtlGetVersion address\n");
		return std::unexpected(ReturnCode::UnexpectedError);
	}

	RTL_OSVERSIONINFOW osvi = { 0 };
	osvi.dwOSVersionInfoSize = sizeof(osvi);

	if (BCRYPT_SUCCESS(pRtlGetVersion(&osvi))) {
		osi.dwMajorVersion = osvi.dwMajorVersion;
		osi.dwMinorVersion = osvi.dwMinorVersion;
		osi.dwBuildNumber = osvi.dwBuildNumber;
	}
	else {
		printf("FAIL: RtlGetVersion failed\n");
		return std::unexpected(ReturnCode::UnexpectedError);
	}

	return osi;
}


static std::expected<struct systemTimeInfo, ReturnCode> gatherUnixTime(void) {
	struct systemTimeInfo sti;

	auto now = std::chrono::system_clock::now();

	sti.time = std::chrono::duration_cast<std::chrono::seconds>(
		now.time_since_epoch()
	).count();

	return sti;
}


static std::expected<struct uptimeInfo, ReturnCode> gatherUptime(void) {
	struct uptimeInfo uti;
	uti.uptime = GetTickCount64();

	return uti;
}


static std::expected<struct memoryInfo, ReturnCode> gatherMemoryInfo(void) {
	struct memoryInfo mmi;

	MEMORYSTATUSEX statex{};
	statex.dwLength = sizeof(statex);

	if (!GlobalMemoryStatusEx(&statex)) {
		printf("FAIL: GlobalMemoryStatusEx failed");
		return std::unexpected(ReturnCode::UnexpectedError);
	}

	mmi.freeRamKB = statex.ullAvailPhys / 1024;

	if (!GetPhysicallyInstalledSystemMemory(&mmi.totalRamKB)) {
		printf("FAIL: GetPhysicallyInstalledSystemMemory failed");
		return std::unexpected(ReturnCode::UnexpectedError);
	}

	return mmi;
}


static ReturnCode localRun(void) {
	auto osi = gatherOSInfo();
	if (!osi) {
		printf("FAIL: Couldn't gather OSInfo\n");
		return ReturnCode::UnexpectedError;
	}

	printf("OS Version: %u.%u.%u\n",
		osi.value().dwMajorVersion,
		osi.value().dwMinorVersion,
		osi.value().dwBuildNumber
	);

	auto stime = gatherUnixTime();
	if (!stime) {
		printf("FAIL: Couldn't gather UNIX time\n");
		return ReturnCode::UnexpectedError;
	}

	printf("Unix time: %llu\n", stime.value().time);

	auto utime = gatherUptime();
	if (!utime) {
		printf("FAIL: Couldn't gather uptime\n");
		return ReturnCode::UnexpectedError;
	}

	printf("Uptime: %llu\n", utime.value().uptime);

	auto memi = gatherMemoryInfo();
	if (!memi) {
		printf("FAIL: Couldn't gather memory info\n");
		return ReturnCode::UnexpectedError;
	}

	printf("Memory: %llu/%llu\n",
		memi.value().freeRamKB,
		memi.value().totalRamKB
	);

	// TODO

	return ReturnCode::Success;
}


int main(void)
{
	if (localRun() != ReturnCode::Success) {
		printf("FAIL: local test run failed");
		return EXIT_FAILURE;
	}

	// TODO

	return EXIT_SUCCESS;
}
