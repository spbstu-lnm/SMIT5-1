/******************************************************************************

	SMIT5-1Shared.h: shared code for SMIT5-1

	NOTES: ...

******************************************************************************/


#pragma once


#include <cstdint>
#include <expected>
#include <string>
#include <array>
#include <print>
#include <lmcons.h>
#include <winnt.h>


inline constexpr auto MAX_DISKS_COUNT = 26;


enum class ReturnCode {
	Success,
	InvalidValue,
	NotImplemented,
	UnexpectedError,
};

enum class RequestType {
	Empty,
	OS,
	SystemTime,
	Uptime,
	Memory,
	Disks,
	FreeSpace,
	ACEFile,
	ACEReg,
	OwnerFile,
	OwnerReg
};


struct OSInfo {
	uint32_t dwMajorVersion = 0;
	uint32_t dwMinorVersion = 0;
	uint32_t dwBuildNumber = 0;
};

struct systemTimeInfo {
	uint64_t timeS = 0;
};

struct uptimeInfo {
	uint64_t uptimeMs = 0;
};

struct memoryInfo {
	uint64_t totalRamKB = 0;
	uint64_t freeRamBytes = 0;
};

struct disksInfo {
	uint32_t leDiskMask = 0b0;
	std::array<std::wstring, MAX_DISKS_COUNT> fileSystemNames{};
	std::array<uint32_t, MAX_DISKS_COUNT> diskTypes{};
};

struct freeSpaceInfo {
	uint32_t leDiskMask = 0b0;
	std::array<uint64_t, MAX_DISKS_COUNT> freeBytes{};
};

// each ACE is a separate struct instance
// ACE query response is terminated with "END" packet
struct ACEInfo {
	PSID subjectSID = 0;
	std::wstring subjectName;

	uint8_t ACEType = 0;
	uint8_t ACEFlags = 0;
	uint32_t accessMask = 0;
};

struct ownerInfo {
	PSID ownerSID = 0;
	std::wstring ownerName;
};

struct request {
	RequestType type = RequestType::Empty;
	std::wstring path;
	HKEY hRootKey = nullptr;
};


// PROTOCOL / WIRE FORMAT
// see SMIT5-1Protocol.h for (de)serialization realizations

// top-level kind of a framed message exchanged over the socket
enum class MessageType : uint8_t {
	HandshakeInit = 1,		// c -> s: client's ECDH public key (plaintext)
	HandshakeResponse = 2,	// s -> c: server's ECDH public key (plaintext)
	Request = 3,			// c -> s: AES-GCM encrypted request
	Response = 4,			// s -> c: AES-GCM encrypted response (status + payload)
};

// check if registry root is valid
[[nodiscard]] inline bool isAllowedPredefinedRoot(HKEY hKey) {
	return hKey == HKEY_CLASSES_ROOT
		|| hKey == HKEY_CURRENT_USER
		|| hKey == HKEY_LOCAL_MACHINE
		|| hKey == HKEY_USERS
		|| hKey == HKEY_CURRENT_CONFIG;
}


[[nodiscard]] inline std::expected<std::wstring, ReturnCode> getDiskNameFromIndex(int idx) {
	if (idx < 0 || idx >= static_cast<int>(MAX_DISKS_COUNT)) {
		std::println(stderr, "FAIL: disk index lies outside of allowed range");
		return std::unexpected(ReturnCode::InvalidValue);
	}

	std::wstring res = L"A:\\";
	res[0] = static_cast<wchar_t>(L'A' + idx);

	return res;
}
