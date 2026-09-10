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


[[nodiscard]] std::expected<std::wstring, ReturnCode> getDiskNameFromIndex(int idx) {
	if (idx < 0 || idx >= static_cast<int>(MAX_DISKS_COUNT)) {
		std::println(stderr, "FAIL: disk index lies outside of allowed range");
		return std::unexpected(ReturnCode::InvalidValue);
	}

	std::wstring res = L"A:\\";
	res[0] = static_cast<wchar_t>(L'A' + idx);

	return res;
}
