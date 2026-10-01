/******************************************************************************

	SMIT5-1ClientNet.cpp: ServerConnection implementation

******************************************************************************/

#include "SMIT5-1ClientNet.h"
#include "SMIT5-1Protocol.h"
#include <cstring>


ServerConnection::ServerConnection(SOCKET s, crypto::KeyHandle sessionKey)
	: socket_(s), sessionKey_(std::move(sessionKey)) {
}

ServerConnection::ServerConnection(ServerConnection&& other) noexcept
	: socket_(other.socket_), sessionKey_(std::move(other.sessionKey_)) {
	other.socket_ = INVALID_SOCKET;
}

ServerConnection& ServerConnection::operator=(ServerConnection&& other) noexcept {
	if (this != &other) {
		if (socket_ != INVALID_SOCKET) closesocket(socket_);
		socket_ = other.socket_;
		sessionKey_ = std::move(other.sessionKey_);
		other.socket_ = INVALID_SOCKET;
	}
	return *this;
}

ServerConnection::~ServerConnection() {
	if (socket_ != INVALID_SOCKET) closesocket(socket_);
}


std::expected<ServerConnection, ReturnCode> ServerConnection::connectTo(
	const std::wstring& hostOrIp, uint16_t port)
{
	const SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET) {
		std::println(stderr, "FAIL: socket() failed (code {})", WSAGetLastError());
		return std::unexpected(ReturnCode::UnexpectedError);
	}

	ADDRINFOW hints{};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	ADDRINFOW* resolved = nullptr;
	const std::wstring portStr = std::to_wstring(port);

	if (GetAddrInfoW(hostOrIp.c_str(), portStr.c_str(), &hints, &resolved) != 0 || !resolved) {
		std::println(stderr, "FAIL: couldn't resolve server address");
		closesocket(s);
		return std::unexpected(ReturnCode::UnexpectedError);
	}

	const int rc = connect(s, resolved->ai_addr, static_cast<int>(resolved->ai_addrlen));
	FreeAddrInfoW(resolved);

	if (rc == SOCKET_ERROR) {
		std::println(stderr, "FAIL: connect() failed (code {})", WSAGetLastError());
		closesocket(s);
		return std::unexpected(ReturnCode::UnexpectedError);
	}

	auto keyResult = performHandshake(s);
	if (!keyResult) {
		closesocket(s);
		return std::unexpected(keyResult.error());
	}

	return ServerConnection{ s, std::move(*keyResult) };
}


std::expected<crypto::KeyHandle, ReturnCode> ServerConnection::performHandshake(SOCKET s) {
	auto own = crypto::EcdhKeyPair::generate();
	if (!own) return std::unexpected(own.error());

	auto ourPub = own->exportPublicBlob();
	if (!ourPub) return std::unexpected(ourPub.error());

	std::vector<uint8_t> initMsg;
	initMsg.reserve(1 + ourPub->size());
	initMsg.push_back(static_cast<uint8_t>(MessageType::HandshakeInit));
	initMsg.insert(initMsg.end(), ourPub->begin(), ourPub->end());

	if (const auto rc = sendFrame(s, initMsg); rc != ReturnCode::Success) {
		return std::unexpected(rc);
	}

	auto respFrame = recvFrame(s);
	if (!respFrame) return std::unexpected(respFrame.error());

	if (respFrame->empty() || static_cast<MessageType>((*respFrame)[0]) != MessageType::HandshakeResponse) {
		std::println(stderr, "FAIL: expected HandshakeResponse, got something else");
		return std::unexpected(ReturnCode::UnexpectedError);
	}

	const std::span<const uint8_t> serverPub{ respFrame->data() + 1, respFrame->size() - 1 };

	return own->deriveAesKey(serverPub);
}


ReturnCode ServerConnection::sendFrame(SOCKET s, std::span<const uint8_t> msg) {
	std::vector<uint8_t> framed;
	framed.reserve(4 + msg.size());

	const uint32_t beLen = htonl(static_cast<uint32_t>(msg.size()));
	const auto* lenBytes = reinterpret_cast<const uint8_t*>(&beLen);
	framed.insert(framed.end(), lenBytes, lenBytes + 4);
	framed.insert(framed.end(), msg.begin(), msg.end());

	size_t sent = 0;
	while (sent < framed.size()) {
		const int n = send(s, reinterpret_cast<const char*>(framed.data() + sent),
			static_cast<int>(framed.size() - sent), 0);

		if (n == SOCKET_ERROR) {
			std::println(stderr, "FAIL: send() failed (code {})", WSAGetLastError());
			return ReturnCode::UnexpectedError;
		}
		sent += static_cast<size_t>(n);
	}

	return ReturnCode::Success;
}


std::expected<std::vector<uint8_t>, ReturnCode> ServerConnection::recvFrame(SOCKET s) {
	// sanity cap, mirrors MAX_FRAME_BYTES on the server
	constexpr uint32_t MAX_FRAME_BYTES = 1u * 1024u * 1024u;

	const auto recvExact = [&](uint8_t* dst, size_t n) -> bool {
		size_t got = 0;
		while (got < n) {
			const int r = recv(s, reinterpret_cast<char*>(dst + got), static_cast<int>(n - got), 0);
			if (r <= 0) return false; // connection closed or error
			got += static_cast<size_t>(r);
		}
		return true;
		};

	uint8_t lenBuf[4];
	if (!recvExact(lenBuf, sizeof(lenBuf))) {
		std::println(stderr, "FAIL: connection closed while reading frame length");
		return std::unexpected(ReturnCode::UnexpectedError);
	}

	uint32_t beLen;
	std::memcpy(&beLen, lenBuf, sizeof(beLen));
	const uint32_t frameLen = ntohl(beLen);

	if (frameLen > MAX_FRAME_BYTES) {
		std::println(stderr, "FAIL: server sent an oversized frame ({} bytes)", frameLen);
		return std::unexpected(ReturnCode::UnexpectedError);
	}

	std::vector<uint8_t> payload(frameLen);
	if (!recvExact(payload.data(), frameLen)) {
		std::println(stderr, "FAIL: connection closed while reading frame payload");
		return std::unexpected(ReturnCode::UnexpectedError);
	}

	return payload;
}


std::expected<std::vector<uint8_t>, ReturnCode> ServerConnection::sendRequest(const request& req) {
	const auto reqBytes = proto::serializeRequest(req);

	auto encrypted = crypto::aesGcmEncrypt(sessionKey_.get(), reqBytes);
	if (!encrypted) return std::unexpected(encrypted.error());

	std::vector<uint8_t> msg;
	msg.reserve(1 + encrypted->size());
	msg.push_back(static_cast<uint8_t>(MessageType::Request));
	msg.insert(msg.end(), encrypted->begin(), encrypted->end());

	if (const auto rc = sendFrame(socket_, msg); rc != ReturnCode::Success) {
		return std::unexpected(rc);
	}

	auto respFrame = recvFrame(socket_);
	if (!respFrame) return std::unexpected(respFrame.error());

	if (respFrame->empty() || static_cast<MessageType>((*respFrame)[0]) != MessageType::Response) {
		std::println(stderr, "FAIL: unexpected message type in response");
		return std::unexpected(ReturnCode::UnexpectedError);
	}

	const std::span<const uint8_t> encryptedBody{ respFrame->data() + 1, respFrame->size() - 1 };

	auto plain = crypto::aesGcmDecrypt(sessionKey_.get(), encryptedBody);
	if (!plain) return std::unexpected(plain.error());

	if (plain->empty()) {
		std::println(stderr, "FAIL: empty response body (missing status byte)");
		return std::unexpected(ReturnCode::UnexpectedError);
	}

	const auto status = static_cast<ReturnCode>((*plain)[0]);
	std::vector<uint8_t> payload(plain->begin() + 1, plain->end());

	if (status != ReturnCode::Success) {
		return std::unexpected(status);
	}

	return payload;
}
