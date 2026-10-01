/******************************************************************************

	SMIT5-1Info.h : system-info gathering functions

	moved here from SMIT5-1.cpp

******************************************************************************/

#pragma once

#include "SMIT5-1Shared.h"
#include <expected>
#include <vector>


[[nodiscard]] std::expected<OSInfo, ReturnCode> gatherOSInfo();
[[nodiscard]] std::expected<systemTimeInfo, ReturnCode> gatherUnixTime();
[[nodiscard]] std::expected<uptimeInfo, ReturnCode> gatherUptime();
[[nodiscard]] std::expected<memoryInfo, ReturnCode> gatherMemoryInfo();
[[nodiscard]] std::expected<disksInfo, ReturnCode> gatherDisksInfo();
[[nodiscard]] std::expected<freeSpaceInfo, ReturnCode> gatherFreeSpaceInfo();
[[nodiscard]] std::expected<std::vector<ACEInfo>, ReturnCode> 
	gatherACEInfo(const request& req);

[[nodiscard]] std::expected<std::vector<ownerInfo>, ReturnCode> 
	gatherOwnerInfo(const request& req);
