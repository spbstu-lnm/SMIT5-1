/******************************************************************************

	SMIT5-1.cpp: console application entry point --- SERVER

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
#include "SMIT5-1Shared.h"


// CONSTANTS	===============================================================
// also see header file

// used for local run's ACEInfo folder/file request
inline constexpr auto TEST_FILEPATH = L"S:\\Files";

// used for local run's ACEInfo reg key request
inline constexpr auto TEST_RKEY = HKEY_CURRENT_USER;
inline constexpr auto TEST_REGPATH = L"SOFTWARE";

// GLOBALS	===================================================================
// TODO


// STRUCTS definition in header file


// PROTOTYPES	===============================================================
[[nodiscard]] static std::expected<OSInfo, ReturnCode> gatherOSInfo();
[[nodiscard]] static std::expected<systemTimeInfo, ReturnCode> gatherUnixTime();
[[nodiscard]] static std::expected<uptimeInfo, ReturnCode> gatherUptime();
[[nodiscard]] static std::expected<memoryInfo, ReturnCode> gatherMemoryInfo();
[[nodiscard]] static std::expected<disksInfo, ReturnCode> gatherDisksInfo();
[[nodiscard]] static std::expected<freeSpaceInfo, ReturnCode> gatherFreeSpaceInfo();
[[nodiscard]] static std::expected<std::vector<ACEInfo>, ReturnCode> gatherACEInfo(request);
[[nodiscard]] static std::expected<std::vector<ownerInfo>, ReturnCode> gatherOwnerInfo(request);

[[nodiscard]] static ReturnCode localRun();

// FUNCTIONS	===============================================================
static std::expected<OSInfo, ReturnCode> gatherOSInfo() {
	// RAII-wrapper for HMODULE
	struct LibraryDeleter {
		void operator()(HMODULE h) const { if (h) FreeLibrary(h); }
	};

	std::unique_ptr<std::remove_pointer_t<HMODULE>, LibraryDeleter> \
		ntdll{ LoadLibraryW(L"ntdll.dll") };

	if (!ntdll) {
		std::println(stderr, "FAIL: Unable to load ntdll.dll");
		return std::unexpected(ReturnCode::UnexpectedError);
	}

	auto pRtlGetVersion = std::bit_cast<PFN_RtlGetVersion>(
		GetProcAddress(ntdll.get(), "RtlGetVersion")
	);

	if (!pRtlGetVersion) {
		std::println(stderr, "FAIL: Couldn't resolve RtlGetVersion address");
		return std::unexpected(ReturnCode::UnexpectedError);
	}

	RTL_OSVERSIONINFOW osvi{ .dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW) };

	if (!BCRYPT_SUCCESS(pRtlGetVersion(&osvi))) {
		std::println(stderr, "FAIL: RtlGetVersion failed");
		return std::unexpected(ReturnCode::UnexpectedError);
	}

	return OSInfo{
		.dwMajorVersion = osvi.dwMajorVersion,
		.dwMinorVersion = osvi.dwMinorVersion,
		.dwBuildNumber = osvi.dwBuildNumber
	};
}


static std::expected<systemTimeInfo, ReturnCode> gatherUnixTime() {
	const auto now = std::chrono::system_clock::now();
	const auto seconds = std::chrono::duration_cast<std::chrono::seconds> \
		(now.time_since_epoch()).count();

	return systemTimeInfo{ .timeS = static_cast<uint64_t>(seconds) };
}


static std::expected<uptimeInfo, ReturnCode> gatherUptime() {
	return uptimeInfo{ .uptimeMs = GetTickCount64() };
}


static std::expected<memoryInfo, ReturnCode> gatherMemoryInfo() {
	MEMORYSTATUSEX statex{ .dwLength = sizeof(MEMORYSTATUSEX) };

	if (!GlobalMemoryStatusEx(&statex)) {
		std::println(stderr, "FAIL: GlobalMemoryStatusEx failed");
		return std::unexpected(ReturnCode::UnexpectedError);
	}

	memoryInfo mmi{
		.freeRamBytes = statex.ullAvailPhys
	};

	if (!GetPhysicallyInstalledSystemMemory(&mmi.totalRamKB)) {
		std::println(stderr, "FAIL: GetPhysicallyInstalledSystemMemory failed");
		return std::unexpected(ReturnCode::UnexpectedError);
	}

	return mmi;
}


static std::expected<disksInfo, ReturnCode> gatherDisksInfo() {
	disksInfo di{ .leDiskMask = GetLogicalDrives() };

	if (!di.leDiskMask) {
		std::println(stderr, "FAIL: GetLogicalDrives failed");
		return std::unexpected(ReturnCode::UnexpectedError);
	}

	for (int i = 0; i < MAX_DISKS_COUNT; i++) {
		if (!((di.leDiskMask >> i) & 0b1)) continue;

		auto diskName = getDiskNameFromIndex(i);
		
		if (!diskName) {
			std::println(stderr, "FAIL: Couldn't get disk's name from index");
			return std::unexpected(diskName.error());
		}

		di.diskTypes[i] = GetDriveTypeW(diskName.value().c_str());

		// GetVolumeInformationW requires fixed-size buffer
		di.fileSystemNames[i].resize(MAX_PATH + 1, L'\0');

		if (!GetVolumeInformationW(
			diskName.value().c_str(),
			nullptr,
			0,
			nullptr,
			nullptr,
			nullptr,
			di.fileSystemNames[i].data(),
			static_cast<DWORD>(di.fileSystemNames[i].size())
		)) {
			std::println(stderr, "FAIL: GetVolumeInformationW failed");
			return std::unexpected(ReturnCode::UnexpectedError);
		}

		// reducing buffer to actual size
		di.fileSystemNames[i].resize(std::wcslen(di.fileSystemNames[i].c_str()));
	}

	return di;
}


static std::expected<freeSpaceInfo, ReturnCode> gatherFreeSpaceInfo() {
	freeSpaceInfo fsi{ .leDiskMask = GetLogicalDrives() };

	if (!fsi.leDiskMask) {
		std::println(stderr, "FAIL: GetLogicalDrives failed");
		return std::unexpected(ReturnCode::UnexpectedError);
	}

	for (int i = 0; i < MAX_DISKS_COUNT; i++) {
		if (!((fsi.leDiskMask >> i) & 0b1)) continue;

		auto diskName = getDiskNameFromIndex(i);

		if (!diskName) {
			std::println(stderr, "FAIL: Couldn't get disk's name from index");
			return std::unexpected(diskName.error());
		}

		fsi.freeBytes[i] = std::filesystem::space(diskName.value()).free;
	}

	return fsi;
}


static std::expected<std::vector<ACEInfo>, ReturnCode> gatherACEInfo(request req) {
	std::vector<ACEInfo> acei{};

	// TODO

	return acei;
}


static std::expected<std::vector<ownerInfo>, ReturnCode> gatherOwnerInfo(request req) {
	std::vector<ownerInfo> oi{};

	// TODO

	return oi;
}


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

	const auto acei = gatherACEInfo(ACEFileRequest);
	if (!acei) {
		std::println(stderr, "FAIL: Couldn't gather ACEInfo for a file");
		return acei.error();
	}

	std::print("\n");

	// TODO

	return ReturnCode::Success;
}


int main()
{
	if (localRun() != ReturnCode::Success) {
		printf("FAIL: local test run failed");
		return EXIT_FAILURE;
	}

	// TODO

	return EXIT_SUCCESS;
}
