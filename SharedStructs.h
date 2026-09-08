/******************************************************************************

	SharedStructs.h: shared structures for SMIT5-1

	NOTES: ...

******************************************************************************/


#pragma once


#include <cstdint>
#include <lmcons.h>
#include <winnt.h>


constexpr auto MAX_DISKS_COUNT = (26);

// fs name most likely will fit in 8 wchars
constexpr auto MAX_FS_NAME_LENGTH = (8);


struct OSInfo {
	uint32_t dwMajorVersion = 0;
	uint32_t dwMinorVersion = 0;
	uint32_t dwBuildNumber = 0;
};

struct systemTimeInfo {
	uint64_t time = 0;
};

struct uptimeInfo {
	uint64_t uptime = 0;
};

struct memoryInfo {
	uint64_t totalRamKB = 0;
	uint64_t freeRamKB = 0;
};

struct diskInfo {
	wchar_t* fileSystemNames[MAX_DISKS_COUNT][MAX_FS_NAME_LENGTH] = { 0 };
	uint32_t* diskTypes[MAX_DISKS_COUNT] = { 0 };
};

struct freeSpaceInfo {
	uint64_t* freeBytes[MAX_DISKS_COUNT] = { 0 };
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
