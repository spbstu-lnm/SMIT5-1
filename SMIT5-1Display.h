/******************************************************************************

	SMIT5-1Display.h: console presentation layer

	Implements the specific output-format requirements from the lab text:

		"Access rights output must include: subject SID, subject name,
		 ACE types, the scope of the granted rights, the set bit numbers
		 in the access mask, and the names of those bits for the current
		 object type."

		"Owner output must contain the SID and the owner's name."

		"Current time and uptime must be shown in seconds, minutes,
		 hours, days, etc."

	Nothing here talks to the network or to Win32 security APIs directly;
	it only turns the plain data structures from SMIT5-1Protocol.h into
	readable text. Fully implemented (no TODOs) -- this part doesn't depend
	on how the UI collects input, so there was nothing to leave as an
	exercise.

******************************************************************************/

#pragma once

#include "SMIT5-1Client.h"
#include "SMIT5-1Shared.h"
#include "SMIT5-1Protocol.h"
#include <vector>
#include <string>
#include <span>


namespace display {

	enum class ObjectKind { File, Registry };

	// SID in "S-1-5-..." form via ConvertSidToStringSidW;
	// placeholder string for invalid SID
	[[nodiscard]] std::wstring sidToString(std::span<const uint8_t> sidBytes);

	// names of every bit set in `mask`
	// unknown bits are reported numerically
	[[nodiscard]] std::vector<std::wstring> decodeAccessMask(uint32_t mask, ObjectKind kind);

	// "Allowed" / "Denied" / "Audit" / "<type N>" for an unrecognized value
	[[nodiscard]] std::wstring aceTypeName(uint8_t aceType);

	// names of every ACE flag that's set
	[[nodiscard]] std::vector<std::wstring> aceFlagsNames(uint8_t aceFlags);

	// seconds-since-epoch -> local calendar date/time string
	[[nodiscard]] std::wstring formatUnixTime(uint64_t timeS);

	// milliseconds -> "D d, H h, M min, S s (total ... ms)"
	[[nodiscard]] std::wstring formatDuration(uint64_t ms);

	// human-readable byte count -> "1.23 GB" / "456 MB" / ...
	[[nodiscard]] std::wstring formatByteSize(uint64_t bytes);


	// pretty-printers for each response type --- these are what SMIT5-1Client.cpp
	// calls after a successful proto::deserialize*()
	void printOSInfo(const OSInfo& v);
	void printSystemTime(const systemTimeInfo& v);
	void printUptime(const uptimeInfo& v);
	void printMemoryInfo(const memoryInfo& v);
	void printDisksInfo(const disksInfo& v);
	void printFreeSpaceInfo(const freeSpaceInfo& v);
	void printACEList(const std::vector<proto::WireACEEntry>& aces, ObjectKind kind);
	void printOwnerList(const std::vector<proto::WireOwnerEntry>& owners);

} // namespace display
