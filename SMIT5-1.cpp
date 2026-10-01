/******************************************************************************

	SMIT5-1.cpp : console application entry point --- SERVER

	C++23

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
		see SMIT5-1Shared.h for the data structs and SMIT5-1Protocol.h for
		the wire (de)serialization format


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
			* received and processed queries

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
			(see SMIT5-1Crypto.h for the handshake + AES-GCM implementation)

		- IO Completion Ports used to handle many users at once
			(see SMIT5-1Server.cpp)

		- info-gathering functions are moved to SMIT5-1Info.h/.cpp
			(shared between localRun() and the network server)

******************************************************************************/


#include "SMIT5-1.h"
#include "SMIT5-1Shared.h"
#include "SMIT5-1Info.h"
#include "SMIT5-1Server.h"


// CONSTANTS	===============================================================
// also see header file

// used for local run's ACEInfo folder/file request
inline constexpr auto TEST_FILEPATH = L"S:\\Files";

// used for local run's ACEInfo reg key request
// not constexpr (isn't compile-time constant)
inline const auto TEST_RKEY = HKEY_CURRENT_USER;
inline constexpr auto TEST_REGPATH = L"SOFTWARE";

// port the server listens on for client connections
inline constexpr uint16_t SERVER_PORT = 9000;


// PROTOTYPES	===============================================================
[[nodiscard]] static ReturnCode localRun();


// FUNCTIONS	===============================================================
static ReturnCode localRun() {
	const auto osi = gatherOSInfo();
	if (!osi) {
		std::println(stderr, "FAIL: Couldn't gather OSInfo");
		return osi.error();
	}

	std::println("OS Version: {}.{}.{}",
		osi->dwMajorVersion,
		osi->dwMinorVersion,
		osi->dwBuildNumber
	);

	const auto stime = gatherUnixTime();
	if (!stime) {
		std::println(stderr, "FAIL: Couldn't gather UNIX time");
		return stime.error();
	}

	std::println("Unix time: {}", stime->timeS);

	const auto utime = gatherUptime();
	if (!utime) {
		std::println(stderr, "FAIL: Couldn't gather uptime");
		return utime.error();
	}

	std::println("Uptime: {}", utime->uptimeMs);

	const auto memi = gatherMemoryInfo();
	if (!memi) {
		std::println(stderr, "FAIL: Couldn't gather memoryInfo");
		return memi.error();
	}

	std::println("Memory: {} / {} KB ",
		memi->freeRamBytes / 1024,
		memi->totalRamKB
	);

	const auto di = gatherDisksInfo();
	if (!di) {
		std::println(stderr, "FAIL: Couldn't gather disksInfo");
		return di.error();
	}

	std::print("\n");

	for (int i = 0; i < MAX_DISKS_COUNT; i++) {
		if (!((di->leDiskMask >> i) & 0b1)) continue;

		// workaround to format std::wstring
		std::wcout << std::format(L"Disk {}: {} ({})",
			i, di->diskTypes[i], di->fileSystemNames[i]) << '\n';
	}

	const auto fsi = gatherFreeSpaceInfo();
	if (!fsi) {
		std::println(stderr, "FAIL: Couldn't gather freeSpaceInfo");
		return fsi.error();
	}

	std::print("\n");

	for (int i = 0; i < MAX_DISKS_COUNT; i++) {
		if (!((fsi->leDiskMask >> i) & 0b1)) continue;

		std::println("Disk {}: {} bytes free", i, fsi->freeBytes[i]);
	}

	request ACEFileRequest = {
		.type = RequestType::ACEFile,
		.path = TEST_FILEPATH
	};

	const auto aceFile = gatherACEInfo(ACEFileRequest);
	if (!aceFile) {
		std::println(stderr, "FAIL: Couldn't gather ACEInfo for a file");
		return aceFile.error();
	}

	std::print("\n");

	for (const auto& ace : aceFile.value()) {
		std::wcout << std::format(
			L"ACE (file): {} | type {} | flags {:#04x} | mask {:#010x}",
			ace.subjectName, ace.ACEType, ace.ACEFlags, ace.accessMask
		) << '\n';
	}

	request ownerFileRequest = {
		.type = RequestType::OwnerFile,
		.path = TEST_FILEPATH
	};

	const auto ownerFile = gatherOwnerInfo(ownerFileRequest);
	if (!ownerFile) {
		std::println(stderr, "FAIL: Couldn't gather ownerInfo for a file");
		return ownerFile.error();
	}

	std::print("\n");

	for (const auto& owner : ownerFile.value()) {
		std::wcout << std::format(L"Owner (file): {}", owner.ownerName) << '\n';
	}

	request ACERegRequest = {
		.type = RequestType::ACEReg,
		.path = TEST_REGPATH,
		.hRootKey = TEST_RKEY
	};

	const auto aceReg = gatherACEInfo(ACERegRequest);
	if (!aceReg) {
		std::println(stderr, "FAIL: Couldn't gather ACEInfo for a reg key");
		return aceReg.error();
	}

	std::print("\n");

	for (const auto& ace : aceReg.value()) {
		std::wcout << std::format(
			L"ACE (reg): {} | type {} | flags {:#04x} | mask {:#010x}",
			ace.subjectName, ace.ACEType, ace.ACEFlags, ace.accessMask
		) << '\n';
	}

	request ownerRegRequest = {
		.type = RequestType::OwnerReg,
		.path = TEST_REGPATH,
		.hRootKey = TEST_RKEY
	};

	const auto ownerReg = gatherOwnerInfo(ownerRegRequest);
	if (!ownerReg) {
		std::println(stderr, "FAIL: Couldn't gather ownerInfo for a reg key");
		return ownerReg.error();
	}

	std::print("\n");

	for (const auto& owner : ownerReg.value()) {
		std::wcout << std::format(L"Owner (reg): {}", owner.ownerName) << '\n';
	}

	// separate cleanup for local run
	// same cleanup as in SMIT5-1Server.cpp
	for (const auto& ace : aceFile.value())  if (ace.subjectSID) LocalFree(ace.subjectSID);
	for (const auto& ace : aceReg.value())   if (ace.subjectSID) LocalFree(ace.subjectSID);
	for (const auto& o : ownerFile.value())  if (o.ownerSID)     LocalFree(o.ownerSID);
	for (const auto& o : ownerReg.value())   if (o.ownerSID)     LocalFree(o.ownerSID);

	return ReturnCode::Success;
}


int main()
{
#ifdef DEBUG

	if (localRun() != ReturnCode::Success) {
		printf("FAIL: local test run failed");
		return EXIT_FAILURE;
	}

#else

	if (!runServer(SERVER_PORT)) {
		std::println(stderr, "FAIL: server failed to start");
		return EXIT_FAILURE;
	}

#endif // DEBUG

	return EXIT_SUCCESS;
}
