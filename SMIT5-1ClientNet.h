/******************************************************************************

	SMIT5-1ClientNet.h: one connection to a SMIT5-1 server

	Implements, from the client side, exactly the per-connection protocol
	that SMIT5-1Server.cpp implements on the server side:

		1. TCP connect()
		2. generate an ephemeral ECDH P-384 key pair (SMIT5-1Crypto.h),
		   send its public part as a HandshakeInit frame (plaintext)
		3. receive the server's HandshakeResponse frame (its own public
		   part, plaintext), derive the AES-256-GCM session key from it
		4. from then on: sendRequest() encrypts + frames a `request` and
		   returns the decrypted, status-checked response payload

	client connects to a single server and does not require IOCP

******************************************************************************/

#pragma once

#include "SMIT5-1Client.h"
#include "SMIT5-1Shared.h"
#include "SMIT5-1Crypto.h"
#include <expected>
#include <span>
#include <vector>
#include <string>


class ServerConnection {
public:
	// resolves `hostOrIp`, connects on `port`, performs the ECDH handshake
	// and returns a ready-to-use connection
	[[nodiscard]] static std::expected<ServerConnection, ReturnCode> connectTo(
		const std::wstring& hostOrIp, uint16_t port);

	ServerConnection(const ServerConnection&) = delete;
	ServerConnection& operator=(const ServerConnection&) = delete;

	ServerConnection(ServerConnection&& other) noexcept;
	ServerConnection& operator=(ServerConnection&& other) noexcept;

	~ServerConnection();

	// encrypts + sends `req`, blocks for the response, decrypts it and
	// returns the response PAYLOAD (status byte already checked) ---
	// ready to be handed to one of the proto::deserialize*() functions.
	// fails if the transport/crypto layer fails, OR if the server replied
	// with a ReturnCode other than Success (that ReturnCode is forwarded
	// as the error)
	[[nodiscard]] std::expected<std::vector<uint8_t>, ReturnCode> sendRequest(const request& req);

private:
	ServerConnection(SOCKET s, crypto::KeyHandle sessionKey);

	[[nodiscard]] static std::expected<crypto::KeyHandle, ReturnCode> performHandshake(SOCKET s);

	// raw framing helpers, same wire format as the server
	// (SMIT5-1Server.cpp's postRecv/postSend): [4-byte big-endian length][payload]. 
	// The client can afford to block here since it only ever has one connection open.
	[[nodiscard]] static ReturnCode sendFrame(SOCKET s, std::span<const uint8_t> msg);
	[[nodiscard]] static std::expected<std::vector<uint8_t>, ReturnCode> recvFrame(SOCKET s);

	SOCKET socket_ = INVALID_SOCKET;
	crypto::KeyHandle sessionKey_;
};
