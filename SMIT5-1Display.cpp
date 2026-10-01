/******************************************************************************

	SMIT5-1Display.cpp

******************************************************************************/

#include "SMIT5-1Display.h"
#include <array>


namespace {

	struct MaskBit { uint32_t bit; const wchar_t* name; };

	// generic/standard rights --- apply to (almost) any securable object
	constexpr std::array GENERIC_BITS{
		MaskBit{ GENERIC_ALL,     L"GENERIC_ALL" },
		MaskBit{ GENERIC_EXECUTE, L"GENERIC_EXECUTE" },
		MaskBit{ GENERIC_WRITE,   L"GENERIC_WRITE" },
		MaskBit{ GENERIC_READ,    L"GENERIC_READ" },
		MaskBit{ DELETE,          L"DELETE" },
		MaskBit{ READ_CONTROL,    L"READ_CONTROL" },
		MaskBit{ WRITE_DAC,       L"WRITE_DAC" },
		MaskBit{ WRITE_OWNER,     L"WRITE_OWNER" },
		MaskBit{ SYNCHRONIZE,     L"SYNCHRONIZE" },
	};

	// object-specific rights, file/folder
	constexpr std::array FILE_BITS{
		MaskBit{ FILE_READ_DATA,        L"FILE_READ_DATA (list folder)" },
		MaskBit{ FILE_WRITE_DATA,       L"FILE_WRITE_DATA (create files)" },
		MaskBit{ FILE_APPEND_DATA,      L"FILE_APPEND_DATA (create folders)" },
		MaskBit{ FILE_READ_EA,          L"FILE_READ_EA" },
		MaskBit{ FILE_WRITE_EA,         L"FILE_WRITE_EA" },
		MaskBit{ FILE_EXECUTE,          L"FILE_EXECUTE (traverse folder)" },
		MaskBit{ FILE_DELETE_CHILD,     L"FILE_DELETE_CHILD" },
		MaskBit{ FILE_READ_ATTRIBUTES,  L"FILE_READ_ATTRIBUTES" },
		MaskBit{ FILE_WRITE_ATTRIBUTES, L"FILE_WRITE_ATTRIBUTES" },
	};

	// object-specific rights, registry key
	constexpr std::array REG_BITS{
		MaskBit{ KEY_QUERY_VALUE,        L"KEY_QUERY_VALUE" },
		MaskBit{ KEY_SET_VALUE,          L"KEY_SET_VALUE" },
		MaskBit{ KEY_CREATE_SUB_KEY,     L"KEY_CREATE_SUB_KEY" },
		MaskBit{ KEY_ENUMERATE_SUB_KEYS, L"KEY_ENUMERATE_SUB_KEYS" },
		MaskBit{ KEY_NOTIFY,             L"KEY_NOTIFY" },
		MaskBit{ KEY_CREATE_LINK,        L"KEY_CREATE_LINK" },
	};

	struct FlagBit { uint8_t bit; const wchar_t* name; };

	constexpr std::array ACE_FLAG_BITS{
		FlagBit{ OBJECT_INHERIT_ACE,       L"OBJECT_INHERIT" },
		FlagBit{ CONTAINER_INHERIT_ACE,    L"CONTAINER_INHERIT" },
		FlagBit{ NO_PROPAGATE_INHERIT_ACE, L"NO_PROPAGATE_INHERIT" },
		FlagBit{ INHERIT_ONLY_ACE,         L"INHERIT_ONLY" },
		FlagBit{ INHERITED_ACE,            L"INHERITED" },
	};

	[[nodiscard]] const wchar_t* driveTypeName(uint32_t driveType) {
		switch (driveType) {
		case DRIVE_REMOVABLE: return L"removable";
		case DRIVE_FIXED:     return L"local (fixed)";
		case DRIVE_REMOTE:    return L"network";
		case DRIVE_CDROM:     return L"CD-ROM";
		case DRIVE_RAMDISK:   return L"RAM disk";
		case DRIVE_NO_ROOT_DIR: return L"<no media / not present>";
		default:              return L"unknown";
		}
	}

} // namespace


std::wstring display::sidToString(std::span<const uint8_t> sidBytes) {
	if (sidBytes.empty()) return L"<unresolved>";

	// a PSID is just a pointer to a correctly-formatted binary SID --- it
	// doesn't need to come from LocalAlloc/CryptoAPI, pointing it at bytes
	// we already own is fine as long as the bytes are well-formed
	const PSID pSid = const_cast<PSID>(static_cast<const void*>(sidBytes.data()));

	if (!IsValidSid(pSid)) return L"<invalid SID>";

	LPWSTR sidStr = nullptr;
	if (!ConvertSidToStringSidW(pSid, &sidStr)) return L"<unconvertible SID>";

	std::wstring result{ sidStr };
	LocalFree(sidStr);
	return result;
}


std::vector<std::wstring> display::decodeAccessMask(uint32_t mask, ObjectKind kind) {
	std::vector<std::wstring> names;

	for (const auto& b : GENERIC_BITS) {
		if (mask & b.bit) names.emplace_back(b.name);
	}

	uint32_t covered = 0;
	for (const auto& b : GENERIC_BITS) covered |= b.bit;

	if (kind == ObjectKind::File) {
		for (const auto& b : FILE_BITS) {
			if (mask & b.bit) names.emplace_back(b.name);
			covered |= b.bit;
		}
	}
	else {
		for (const auto& b : REG_BITS) {
			if (mask & b.bit) names.emplace_back(b.name);
			covered |= b.bit;
		}
	}

	if (const uint32_t leftover = mask & ~covered; leftover != 0) {
		names.push_back(std::format(L"<unrecognized bits {:#010x}>", leftover));
	}

	return names;
}


std::wstring display::aceTypeName(uint8_t aceType) {
	switch (aceType) {
	case ACCESS_ALLOWED_ACE_TYPE: return L"Allowed";
	case ACCESS_DENIED_ACE_TYPE:  return L"Denied";
	case SYSTEM_AUDIT_ACE_TYPE:   return L"Audit";
	default: return std::format(L"<type {}>", aceType);
	}
}


std::vector<std::wstring> display::aceFlagsNames(uint8_t aceFlags) {
	std::vector<std::wstring> names;

	for (const auto& f : ACE_FLAG_BITS) {
		if (aceFlags & f.bit) names.emplace_back(f.name);
	}

	if (names.empty()) names.emplace_back(L"explicit (not inherited)");

	return names;
}


std::wstring display::formatUnixTime(uint64_t timeS) {
	const auto t = static_cast<std::time_t>(timeS);

	std::tm tmBuf{};
	if (localtime_s(&tmBuf, &t) != 0) return L"<invalid time>";

	wchar_t buf[64]{};
	std::wcsftime(buf, std::size(buf), L"%Y-%m-%d %H:%M:%S (local time)", &tmBuf);

	return buf;
}


std::wstring display::formatDuration(uint64_t ms) {
	const uint64_t totalSeconds = ms / 1000;
	const uint64_t days = totalSeconds / 86400;
	const uint64_t hours = (totalSeconds % 86400) / 3600;
	const uint64_t minutes = (totalSeconds % 3600) / 60;
	const uint64_t seconds = totalSeconds % 60;

	return std::format(L"{} d, {} h, {} min, {} s  (total {} ms)", days, hours, minutes, seconds, ms);
}


std::wstring display::formatByteSize(uint64_t bytes) {
	static constexpr const wchar_t* UNITS[] = { L"B", L"KB", L"MB", L"GB", L"TB" };

	double value = static_cast<double>(bytes);
	size_t unit = 0;

	while (value >= 1024.0 && unit + 1 < std::size(UNITS)) {
		value /= 1024.0;
		unit++;
	}

	return std::format(L"{:.2f} {} ({} bytes)", value, UNITS[unit], bytes);
}


void display::printOSInfo(const OSInfo& v) {
	std::wcout << std::format(L"OS: Windows {}.{}.{}\n",
		v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber);
}

void display::printSystemTime(const systemTimeInfo& v) {
	std::wcout << L"Server time : " << formatUnixTime(v.timeS)
		<< L"  (unix timestamp: " << v.timeS << L" s)\n";
}

void display::printUptime(const uptimeInfo& v) {
	std::wcout << L"Server uptime: " << formatDuration(v.uptimeMs) << L"\n";
}

void display::printMemoryInfo(const memoryInfo& v) {
	std::wcout << L"Free memory : " << formatByteSize(v.freeRamBytes) << L"\n";
	std::wcout << L"Total memory: " << v.totalRamKB << L" KB\n";
}

void display::printDisksInfo(const disksInfo& v) {
	bool any = false;
	for (int i = 0; i < static_cast<int>(MAX_DISKS_COUNT); i++) {
		if (!((v.leDiskMask >> i) & 0b1)) continue;
		any = true;

		const wchar_t letter = static_cast<wchar_t>(L'A' + i);
		std::wcout << std::format(L"{}:  type = {:<16}  fs = {}\n",
			letter, driveTypeName(v.diskTypes[i]),
			v.fileSystemNames[i].empty() ? L"<n/a>" : v.fileSystemNames[i]);
	}
	if (!any) std::wcout << L"(no disks reported)\n";
}

void display::printFreeSpaceInfo(const freeSpaceInfo& v) {
	bool any = false;
	for (int i = 0; i < static_cast<int>(MAX_DISKS_COUNT); i++) {
		if (!((v.leDiskMask >> i) & 0b1)) continue;
		any = true;

		const wchar_t letter = static_cast<wchar_t>(L'A' + i);
		std::wcout << std::format(L"{}:  {} free\n", letter, formatByteSize(v.freeBytes[i]));
	}
	if (!any) std::wcout << L"(no disks reported)\n";
}

void display::printACEList(const std::vector<proto::WireACEEntry>& aces, ObjectKind kind) {
	if (aces.empty()) {
		std::wcout << L"(no explicit ACEs --- a NULL DACL means everyone has full access)\n";
		return;
	}

	for (size_t i = 0; i < aces.size(); i++) {
		const auto& ace = aces[i];

		std::wcout << L"--- ACE " << (i + 1) << L"/" << aces.size() << L" ---\n";
		std::wcout << L"  Subject SID : " << sidToString(ace.sid) << L"\n";
		std::wcout << L"  Subject name: " << ace.subjectName << L"\n";
		std::wcout << L"  ACE type    : " << aceTypeName(ace.aceType) << L"\n";

		std::wcout << L"  Scope       : ";
		for (const auto& f : aceFlagsNames(ace.aceFlags)) std::wcout << f << L"  ";
		std::wcout << L"\n";

		std::wcout << L"  Access mask : " << std::format(L"{:#010x}", ace.accessMask) << L"\n";
		std::wcout << L"  Set bit numbers: ";
		bool firstBit = true;
		for (uint32_t bit = 0; bit < 32; ++bit) {
			if ((ace.accessMask & (uint32_t{ 1 } << bit)) == 0) continue;
			if (!firstBit) std::wcout << L", ";
			std::wcout << bit;
			firstBit = false;
		}
		if (firstBit) std::wcout << L"none";
		std::wcout << L"\n";
		for (const auto& bit : decodeAccessMask(ace.accessMask, kind)) {
			std::wcout << L"      - " << bit << L"\n";
		}
		std::wcout << L"\n";
	}
}

void display::printOwnerList(const std::vector<proto::WireOwnerEntry>& owners) {
	for (const auto& o : owners) {
		std::wcout << L"Owner SID : " << sidToString(o.sid) << L"\n";
		std::wcout << L"Owner name: " << o.ownerName << L"\n";
	}
}
