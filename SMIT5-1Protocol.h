/******************************************************************************

	SMIT5-1Protocol.h: application-layer wire format

	Framing (handled in SMIT5-1Server.cpp, not here):
		[4-byte big-endian length][payload]
	payload[0] is always a MessageType (see SMIT5-1Shared.h); the rest is:
		HandshakeInit / HandshakeResponse -> raw ECDH public key blob (plaintext)
		Request                           -> AES-GCM frame wrapping a `request`
		Response                          -> AES-GCM frame wrapping [ReturnCode][payload]

	A `request` and every response payload below is encoded with simple
	length-prefixed fields (see ByteWriter/ByteReader) rather than raw struct
	memcpy, so the format doesn't depend on struct padding/alignment and can
	be parsed defensively (every read is bounds-checked).

	NOTE on ACEInfo/ownerInfo lists: the struct comment in SMIT5-1Shared.h
	describes an older idea of streaming each ACE as its own packet
	terminated by an "END" packet. Since the whole exchange here is a single
	request -> single encrypted response (to keep the server stateless), the
	list is instead sent as one count-prefixed array in one response -- same
	information, same per-entry shape, just framed as one message instead of
	N+1 messages.

******************************************************************************/

#pragma once

#include "SMIT5-1.h"
#include "SMIT5-1Shared.h"
#include <vector>
#include <span>
#include <string>
#include <cstring>
#include <expected>

namespace proto {

	// sanity caps so a garbled/hostile length field can't trigger a huge allocation
	inline constexpr uint32_t MAX_WSTRING_CHARS = 32u * 1024u;
	inline constexpr uint32_t MAX_BLOB_BYTES = 64u * 1024u;


	class ByteWriter {
	public:
		void u8(uint8_t v) { buf_.push_back(v); }

		void u32(uint32_t v) {
			const uint32_t be = htonl(v);
			appendRaw(&be, sizeof(be));
		}

		void u64(uint64_t v) {
			// split into two 32-bit halves to use htonl
			const uint32_t hi = htonl(static_cast<uint32_t>(v >> 32));
			const uint32_t lo = htonl(static_cast<uint32_t>(v & 0xFFFFFFFFu));
			appendRaw(&hi, sizeof(hi));
			appendRaw(&lo, sizeof(lo));
		}

		void bytes(std::span<const uint8_t> data) {
			u32(static_cast<uint32_t>(data.size()));
			buf_.insert(buf_.end(), data.begin(), data.end());
		}

		void wstr(const std::wstring& s) {
			u32(static_cast<uint32_t>(s.size()));
			appendRaw(s.data(), s.size() * sizeof(wchar_t));
		}

		[[nodiscard]] std::vector<uint8_t> take() { return std::move(buf_); }

	private:
		void appendRaw(const void* p, size_t n) {
			const auto* b = static_cast<const uint8_t*>(p);
			buf_.insert(buf_.end(), b, b + n);
		}

		std::vector<uint8_t> buf_;
	};


	class ByteReader {
	public:
		explicit ByteReader(std::span<const uint8_t> data) : data_(data) {}

		[[nodiscard]] std::expected<uint8_t, ReturnCode> u8() {
			if (!ensure(1)) return std::unexpected(ReturnCode::InvalidValue);
			return data_[pos_++];
		}

		[[nodiscard]] std::expected<uint32_t, ReturnCode> u32() {
			if (!ensure(4)) return std::unexpected(ReturnCode::InvalidValue);
			uint32_t v;
			std::memcpy(&v, data_.data() + pos_, 4);
			pos_ += 4;
			return ntohl(v);
		}

		[[nodiscard]] std::expected<uint64_t, ReturnCode> u64() {
			auto hi = u32();
			if (!hi) return std::unexpected(hi.error());
			auto lo = u32();
			if (!lo) return std::unexpected(lo.error());
			return (static_cast<uint64_t>(*hi) << 32) | static_cast<uint64_t>(*lo);
		}

		[[nodiscard]] std::expected<std::vector<uint8_t>, ReturnCode> bytes() {
			auto len = u32();
			if (!len) return std::unexpected(len.error());
			if (*len > MAX_BLOB_BYTES || !ensure(*len)) return std::unexpected(ReturnCode::InvalidValue);

			std::vector<uint8_t> out(data_.begin() + pos_, data_.begin() + pos_ + *len);
			pos_ += *len;
			return out;
		}

		[[nodiscard]] std::expected<std::wstring, ReturnCode> wstr() {
			auto len = u32();
			if (!len) return std::unexpected(len.error());
			if (*len > MAX_WSTRING_CHARS) return std::unexpected(ReturnCode::InvalidValue);

			const size_t byteLen = static_cast<size_t>(*len) * sizeof(wchar_t);
			if (!ensure(byteLen)) return std::unexpected(ReturnCode::InvalidValue);

			std::wstring out(*len, L'\0');
			std::memcpy(out.data(), data_.data() + pos_, byteLen);
			pos_ += byteLen;
			return out;
		}

	private:
		[[nodiscard]] bool ensure(size_t n) const { return pos_ + n <= data_.size(); }

		std::span<const uint8_t> data_;
		size_t pos_ = 0;
	};


	// ---- request -----------------------------------------------------------

	[[nodiscard]] inline std::vector<uint8_t> serializeRequest(const request& req) {
		ByteWriter w;
		w.u8(static_cast<uint8_t>(req.type));
		w.wstr(req.path);
		w.u64(reinterpret_cast<uint64_t>(req.hRootKey));
		return w.take();
	}

	[[nodiscard]] inline std::expected<request, ReturnCode> deserializeRequest(std::span<const uint8_t> data) {
		ByteReader r{ data };

		auto type = r.u8();
		if (!type) return std::unexpected(type.error());

		auto path = r.wstr();
		if (!path) return std::unexpected(path.error());

		auto rootKeyRaw = r.u64();
		if (!rootKeyRaw) return std::unexpected(rootKeyRaw.error());

		request req{
			.type = static_cast<RequestType>(*type),
			.path = std::move(*path),
			.hRootKey = reinterpret_cast<HKEY>(static_cast<uintptr_t>(*rootKeyRaw))
		};

		// defense in depth: only ever accept well-known predefined registry
		// roots from the network, never an arbitrary handle value
		if ((req.type == RequestType::ACEReg || req.type == RequestType::OwnerReg)
			&& !isAllowedPredefinedRoot(req.hRootKey))
		{
			return std::unexpected(ReturnCode::InvalidValue);
		}

		return req;
	}


	// ---- response payloads ---------------------------------------------------
	// each function below serializes ONLY the type-specific payload; the
	// ReturnCode status byte that precedes it is written by the server, so a
	// failed request can skip the payload entirely

	[[nodiscard]] inline std::vector<uint8_t> serialize(const OSInfo& v) {
		ByteWriter w;
		w.u32(v.dwMajorVersion);
		w.u32(v.dwMinorVersion);
		w.u32(v.dwBuildNumber);
		return w.take();
	}

	[[nodiscard]] inline std::vector<uint8_t> serialize(const systemTimeInfo& v) {
		ByteWriter w;
		w.u64(v.timeS);
		return w.take();
	}

	[[nodiscard]] inline std::vector<uint8_t> serialize(const uptimeInfo& v) {
		ByteWriter w;
		w.u64(v.uptimeMs);
		return w.take();
	}

	[[nodiscard]] inline std::vector<uint8_t> serialize(const memoryInfo& v) {
		ByteWriter w;
		w.u64(v.totalRamKB);
		w.u64(v.freeRamBytes);
		return w.take();
	}

	[[nodiscard]] inline std::vector<uint8_t> serialize(const disksInfo& v) {
		ByteWriter w;
		w.u32(v.leDiskMask);
		for (int i = 0; i < static_cast<int>(MAX_DISKS_COUNT); i++) {
			if (!((v.leDiskMask >> i) & 0b1)) continue;
			w.u32(v.diskTypes[i]);
			w.wstr(v.fileSystemNames[i]);
		}
		return w.take();
	}

	[[nodiscard]] inline std::vector<uint8_t> serialize(const freeSpaceInfo& v) {
		ByteWriter w;
		w.u32(v.leDiskMask);
		for (int i = 0; i < static_cast<int>(MAX_DISKS_COUNT); i++) {
			if (!((v.leDiskMask >> i) & 0b1)) continue;
			w.u64(v.freeBytes[i]);
		}
		return w.take();
	}

	[[nodiscard]] inline std::vector<uint8_t> serialize(const std::vector<ACEInfo>& v) {
		ByteWriter w;
		w.u32(static_cast<uint32_t>(v.size()));
		for (const auto& ace : v) {
			if (ace.subjectSID && IsValidSid(ace.subjectSID)) {
				w.bytes(std::span<const uint8_t>(
					static_cast<const uint8_t*>(ace.subjectSID),
					GetLengthSid(ace.subjectSID)));
			}
			else {
				w.bytes({}); // empty SID blob -- client should treat as "unresolved"
			}
			w.wstr(ace.subjectName);
			w.u8(ace.ACEType);
			w.u8(ace.ACEFlags);
			w.u32(ace.accessMask);
		}
		return w.take();
	}

	[[nodiscard]] inline std::vector<uint8_t> serialize(const std::vector<ownerInfo>& v) {
		ByteWriter w;
		// OwnerFile/OwnerReg conceptually return a single owner; kept as a
		// count-prefixed array for wire-format consistency with the ACE list
		w.u32(static_cast<uint32_t>(v.size()));
		for (const auto& o : v) {
			if (o.ownerSID && IsValidSid(o.ownerSID)) {
				w.bytes(std::span<const uint8_t>(
					static_cast<const uint8_t*>(o.ownerSID),
					GetLengthSid(o.ownerSID)));
			}
			else {
				w.bytes({});
			}
			w.wstr(o.ownerName);
		}
		return w.take();
	}


	// ---- response payloads: client-side deserialization -----------------------
	// mirror image of the serialize() functions above; the server has no use
	// for these, but they live in the same file as serialize() so the wire
	// format for each message type only has to be written down once and the
	// two sides can never silently drift apart

	[[nodiscard]] inline std::expected<OSInfo, ReturnCode> deserializeOSInfo(std::span<const uint8_t> data) {
		ByteReader r{ data };

		auto major = r.u32(); if (!major) return std::unexpected(major.error());
		auto minor = r.u32(); if (!minor) return std::unexpected(minor.error());
		auto build = r.u32(); if (!build) return std::unexpected(build.error());

		return OSInfo{ .dwMajorVersion = *major, .dwMinorVersion = *minor, .dwBuildNumber = *build };
	}

	[[nodiscard]] inline std::expected<systemTimeInfo, ReturnCode> deserializeSystemTime(std::span<const uint8_t> data) {
		ByteReader r{ data };
		auto t = r.u64();
		if (!t) return std::unexpected(t.error());
		return systemTimeInfo{ .timeS = *t };
	}

	[[nodiscard]] inline std::expected<uptimeInfo, ReturnCode> deserializeUptime(std::span<const uint8_t> data) {
		ByteReader r{ data };
		auto t = r.u64();
		if (!t) return std::unexpected(t.error());
		return uptimeInfo{ .uptimeMs = *t };
	}

	[[nodiscard]] inline std::expected<memoryInfo, ReturnCode> deserializeMemoryInfo(std::span<const uint8_t> data) {
		ByteReader r{ data };

		auto total = r.u64(); if (!total) return std::unexpected(total.error());
		auto free = r.u64(); if (!free) return std::unexpected(free.error());

		return memoryInfo{ .totalRamKB = *total, .freeRamBytes = *free };
	}

	[[nodiscard]] inline std::expected<disksInfo, ReturnCode> deserializeDisksInfo(std::span<const uint8_t> data) {
		ByteReader r{ data };

		auto mask = r.u32();
		if (!mask) return std::unexpected(mask.error());

		disksInfo di{};
		di.leDiskMask = *mask;

		for (int i = 0; i < static_cast<int>(MAX_DISKS_COUNT); i++) {
			if (!((di.leDiskMask >> i) & 0b1)) continue;

			auto type = r.u32(); if (!type) return std::unexpected(type.error());
			auto name = r.wstr(); if (!name) return std::unexpected(name.error());

			di.diskTypes[i] = *type;
			di.fileSystemNames[i] = std::move(*name);
		}

		return di;
	}

	[[nodiscard]] inline std::expected<freeSpaceInfo, ReturnCode> deserializeFreeSpaceInfo(std::span<const uint8_t> data) {
		ByteReader r{ data };

		auto mask = r.u32();
		if (!mask) return std::unexpected(mask.error());

		freeSpaceInfo fsi{};
		fsi.leDiskMask = *mask;

		for (int i = 0; i < static_cast<int>(MAX_DISKS_COUNT); i++) {
			if (!((fsi.leDiskMask >> i) & 0b1)) continue;

			auto bytes = r.u64();
			if (!bytes) return std::unexpected(bytes.error());

			fsi.freeBytes[i] = *bytes;
		}

		return fsi;
	}


	// a single ACE as seen by the client: `sid` is the raw binary SID blob
	// (possibly empty if the server couldn't resolve one). It's intentionally
	// NOT a PSID/ACEInfo like on the server -- the client never allocates
	// through Win32 security APIs, it just displays what it was sent (see
	// SMIT5-1Display.h for turning `sid` into a printable string).
	struct WireACEEntry {
		std::vector<uint8_t> sid;
		std::wstring subjectName;
		uint8_t aceType = 0;
		uint8_t aceFlags = 0;
		uint32_t accessMask = 0;
	};

	struct WireOwnerEntry {
		std::vector<uint8_t> sid;
		std::wstring ownerName;
	};

	[[nodiscard]] inline std::expected<std::vector<WireACEEntry>, ReturnCode> deserializeACEList(std::span<const uint8_t> data) {
		ByteReader r{ data };

		auto count = r.u32();
		if (!count) return std::unexpected(count.error());

		std::vector<WireACEEntry> result;
		result.reserve(*count);

		for (uint32_t i = 0; i < *count; i++) {
			auto sid = r.bytes(); if (!sid) return std::unexpected(sid.error());
			auto name = r.wstr(); if (!name) return std::unexpected(name.error());
			auto type = r.u8(); if (!type) return std::unexpected(type.error());
			auto flags = r.u8(); if (!flags) return std::unexpected(flags.error());
			auto mask = r.u32(); if (!mask) return std::unexpected(mask.error());

			result.push_back(WireACEEntry{
				.sid = std::move(*sid),
				.subjectName = std::move(*name),
				.aceType = *type,
				.aceFlags = *flags,
				.accessMask = *mask
				});
		}

		return result;
	}

	[[nodiscard]] inline std::expected<std::vector<WireOwnerEntry>, ReturnCode> deserializeOwnerList(std::span<const uint8_t> data) {
		ByteReader r{ data };

		auto count = r.u32();
		if (!count) return std::unexpected(count.error());

		std::vector<WireOwnerEntry> result;
		result.reserve(*count);

		for (uint32_t i = 0; i < *count; i++) {
			auto sid = r.bytes(); if (!sid) return std::unexpected(sid.error());
			auto name = r.wstr(); if (!name) return std::unexpected(name.error());

			result.push_back(WireOwnerEntry{ .sid = std::move(*sid), .ownerName = std::move(*name) });
		}

		return result;
	}

} // namespace proto
