/******************************************************************************

	SMIT5-1Info.cpp: system-info gathering functions

******************************************************************************/

#include "SMIT5-1.h"
#include "SMIT5-1Shared.h"
#include "SMIT5-1Info.h"


// RAII-wrapper for anything freed with LocalFree (PSECURITY_DESCRIPTOR, SIDs, ...)
namespace {
	struct LocalFreeDeleter {
		void operator()(void* p) const { if (p) LocalFree(p); }
	};
	using LocalFreePtr = std::unique_ptr<void, LocalFreeDeleter>;
}


static std::expected<PSECURITY_DESCRIPTOR, ReturnCode> getSecurityDescriptor(
	const request& req,
	SECURITY_INFORMATION secInfo,
	PACL* ppDacl,
	PSID* ppOwner)
{
	PSECURITY_DESCRIPTOR pSD = nullptr;
	DWORD err = ERROR_SUCCESS;

	switch (req.type) {
	case RequestType::ACEFile:
	case RequestType::OwnerFile: {
		err = GetNamedSecurityInfoW(
			req.path.c_str(),
			SE_FILE_OBJECT,
			secInfo,
			ppOwner,
			nullptr,
			ppDacl,
			nullptr,
			&pSD
		);
		break;
	}
	case RequestType::ACEReg:
	case RequestType::OwnerReg: {
		// defense in depth: even though the server already validates this
		// on deserialization, never resolve/open an arbitrary handle value
		if (!isAllowedPredefinedRoot(req.hRootKey)) {
			std::println(stderr, "FAIL: rejected non-predefined registry root");
			return std::unexpected(ReturnCode::InvalidValue);
		}

		HKEY hKey = nullptr;
		LSTATUS lstat = RegOpenKeyExW(req.hRootKey, req.path.c_str(), 0, READ_CONTROL, &hKey);

		if (lstat != ERROR_SUCCESS) {
			std::println(stderr, "FAIL: RegOpenKeyExW failed (code {})", lstat);
			return std::unexpected(ReturnCode::UnexpectedError);
		}

		err = GetSecurityInfo(
			hKey,
			SE_REGISTRY_KEY,
			secInfo,
			ppOwner,
			nullptr,
			ppDacl,
			nullptr,
			&pSD
		);

		RegCloseKey(hKey);
		break;
	}
	default:
		std::println(stderr, "FAIL: unsupported request type for security info query");
		return std::unexpected(ReturnCode::InvalidValue);
	}

	if (err != ERROR_SUCCESS) {
		std::println(stderr, "FAIL: couldn't retrieve security descriptor (code {})", err);
		return std::unexpected(ReturnCode::UnexpectedError);
	}

	return pSD;
}


static std::wstring resolveAccountName(PSID pSid) {
	if (!pSid || !IsValidSid(pSid)) return L"<invalid SID>";

	wchar_t nameBuf[UNLEN + 1]{};
	wchar_t domainBuf[UNLEN + 1]{};
	DWORD nameLen = UNLEN + 1;
	DWORD domainLen = UNLEN + 1;
	SID_NAME_USE sidType{};

	if (!LookupAccountSidW(nullptr, pSid, nameBuf, &nameLen, domainBuf, &domainLen, &sidType)) {
		return L"<unknown account>";
	}

	if (domainLen > 0 && domainBuf[0] != L'\0') {
		return std::wstring(domainBuf) + L"\\" + nameBuf;
	}

	return std::wstring(nameBuf);
}


static PSID duplicateSid(PSID pSid) {
	if (!pSid || !IsValidSid(pSid)) return nullptr;

	const DWORD sidLen = GetLengthSid(pSid);
	PSID pCopy = LocalAlloc(LPTR, sidLen);

	if (!pCopy) return nullptr;

	if (!CopySid(sidLen, pCopy, pSid)) {
		LocalFree(pCopy);
		return nullptr;
	}

	return pCopy;
}


std::expected<OSInfo, ReturnCode> gatherOSInfo() {
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


std::expected<systemTimeInfo, ReturnCode> gatherUnixTime() {
	const auto now = std::chrono::system_clock::now();
	const auto seconds = std::chrono::duration_cast<std::chrono::seconds> \
		(now.time_since_epoch()).count();

	return systemTimeInfo{ .timeS = static_cast<uint64_t>(seconds) };
}


std::expected<uptimeInfo, ReturnCode> gatherUptime() {
	return uptimeInfo{ .uptimeMs = GetTickCount64() };
}


std::expected<memoryInfo, ReturnCode> gatherMemoryInfo() {
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


std::expected<disksInfo, ReturnCode> gatherDisksInfo() {
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

		// GetVolumeInformationW fails whenever a removable/optical
		// drive has no media inserted
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
			std::println(stderr,
				"WARN: GetVolumeInformationW failed for disk {} (code {})",
				i, GetLastError());
			di.fileSystemNames[i].clear();
			continue;
		}

		// reducing buffer to actual size
		di.fileSystemNames[i].resize(std::wcslen(di.fileSystemNames[i].c_str()));
	}

	return di;
}


std::expected<freeSpaceInfo, ReturnCode> gatherFreeSpaceInfo() {
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

		// using non-throwing overload to skip bad disks
		std::error_code ec;
		const auto space = std::filesystem::space(diskName.value(), ec);

		if (ec) {
			std::println(stderr,
				"WARN: couldn't get free space for disk {} ({})",
				i, ec.message());
			continue;
		}

		fsi.freeBytes[i] = space.free;
	}

	return fsi;
}


std::expected<std::vector<ACEInfo>, ReturnCode> gatherACEInfo(const request& req) {
	std::vector<ACEInfo> acei{};

	PACL pDacl = nullptr;
	auto sdResult = getSecurityDescriptor(req, DACL_SECURITY_INFORMATION, &pDacl, nullptr);

	if (!sdResult) {
		return std::unexpected(sdResult.error());
	}

	LocalFreePtr sdGuard{ sdResult.value() };

	// a NULL DACL means "everyone has full access" --- nothing to enumerate
	if (!pDacl) {
		return acei;
	}

	ACL_SIZE_INFORMATION aclSize{};
	if (!GetAclInformation(pDacl, &aclSize, sizeof(aclSize), AclSizeInformation)) {
		std::println(stderr, "FAIL: GetAclInformation failed (code {})", GetLastError());
		return std::unexpected(ReturnCode::UnexpectedError);
	}

	acei.reserve(aclSize.AceCount);

	for (DWORD i = 0; i < aclSize.AceCount; i++) {
		LPVOID pAce = nullptr;

		if (!GetAce(pDacl, i, &pAce)) {
			std::println(stderr, "WARN: GetAce failed for index {} (code {})", i, GetLastError());
			continue;
		}

		const auto pHeader = static_cast<PACE_HEADER>(pAce);

		PSID pSid = nullptr;
		ACCESS_MASK mask = 0;

		// only the three most common ACE types are handled here; other,
		// object-specific ACE types (e.g. ACCESS_ALLOWED_OBJECT_ACE, used
		// by Active Directory objects) are intentionally skipped
		switch (pHeader->AceType) {
		case ACCESS_ALLOWED_ACE_TYPE: {
			const auto pTyped = static_cast<ACCESS_ALLOWED_ACE*>(pAce);
			pSid = reinterpret_cast<PSID>(&pTyped->SidStart);
			mask = pTyped->Mask;
			break;
		}
		case ACCESS_DENIED_ACE_TYPE: {
			const auto pTyped = static_cast<ACCESS_DENIED_ACE*>(pAce);
			pSid = reinterpret_cast<PSID>(&pTyped->SidStart);
			mask = pTyped->Mask;
			break;
		}
		case SYSTEM_AUDIT_ACE_TYPE: {
			const auto pTyped = static_cast<SYSTEM_AUDIT_ACE*>(pAce);
			pSid = reinterpret_cast<PSID>(&pTyped->SidStart);
			mask = pTyped->Mask;
			break;
		}
		default:
			continue;
		}

		ACEInfo entry{
			.subjectSID = duplicateSid(pSid),
			.subjectName = resolveAccountName(pSid),
			.ACEType = pHeader->AceType,
			.ACEFlags = pHeader->AceFlags,
			.accessMask = mask
		};

		acei.push_back(std::move(entry));
	}

	return acei;
}


std::expected<std::vector<ownerInfo>, ReturnCode> gatherOwnerInfo(const request& req) {
	std::vector<ownerInfo> oi{};

	PSID pOwnerSid = nullptr;
	auto sdResult = getSecurityDescriptor(req, OWNER_SECURITY_INFORMATION, nullptr, &pOwnerSid);

	if (!sdResult) {
		return std::unexpected(sdResult.error());
	}

	LocalFreePtr sdGuard{ sdResult.value() };

	if (!pOwnerSid) {
		std::println(stderr, "FAIL: security descriptor has no owner SID");
		return std::unexpected(ReturnCode::UnexpectedError);
	}

	oi.push_back(ownerInfo{
		.ownerSID = duplicateSid(pOwnerSid),
		.ownerName = resolveAccountName(pOwnerSid)
		});

	return oi;
}
