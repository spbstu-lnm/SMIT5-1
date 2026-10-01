/******************************************************************************

	SMIT5-1Server.cpp: IOCP-based network server

	one listening socket + AcceptEx keeps a single pending accept at all
	times (reposted after every completion). Every accepted client socket is 
	then associated with the same IO completion port, and a pool of worker
	threads drains GetQueuedCompletionStatus() in parallel

	flow for single connection:
		1. client sends HandshakeInit (its ECDH P-384 public key, plaintext)
		2. server generates its own ephemeral ECDH key pair, derives the
		   AES-256-GCM session key, replies with HandshakeResponse (its
		   own public key, plaintext)
		3. from then on, client sends an encrypted Request, server decrypts
		   it, gathers the requested info (SMIT5-1Info.h) and replies with
		   an encrypted Response

	server never keeps info about a client 
		(beyond the lifetime of its TCP connection)

******************************************************************************/

#include "SMIT5-1.h"
#include "SMIT5-1Shared.h"
#include "SMIT5-1Info.h"
#include "SMIT5-1Crypto.h"
#include "SMIT5-1Protocol.h"
#include "SMIT5-1Server.h"

#include <thread>
#include <vector>
#include <atomic>
#include <memory>
#include <span>
#include <array>
#include <cstring>


namespace {

	// sanity cap on a single framed message, to bound memory use if a peer
	// sends a garbled/hostile length prefix
	constexpr uint32_t MAX_FRAME_BYTES = 1u * 1024u * 1024u;
	constexpr size_t RECV_CHUNK_SIZE = 8192;

	enum class IoOperation { Accept, Recv, Send };

	// first member MUST be the OVERLAPPED --- GetQueuedCompletionStatus() gives
	// back exactly this address, and since OVERLAPPED is the first member we
	// can safely reinterpret_cast it back to PerIoData*
	struct PerIoData {
		OVERLAPPED overlapped{};
		IoOperation op{};
		WSABUF wsaBuf{};
		void* owner = nullptr; // -> ClientContext* (Recv/Send) or AcceptContext* (Accept)
	};

	struct ClientContext {
		SOCKET socket = INVALID_SOCKET;
		sockaddr_in remoteAddr{};

		enum class State { AwaitingHandshake, Ready } state = State::AwaitingHandshake;

		crypto::KeyHandle aesKey; // only valid once state == Ready

		std::vector<uint8_t> recvAccum;                  // bytes received but not yet parsed into frames
		std::array<char, RECV_CHUNK_SIZE> recvChunk{};    // scratch buffer WSARecv writes into

		std::vector<uint8_t> sendBuf;  // currently outgoing frame; must stay alive until WSASend completes
		size_t sendOffset = 0;         // how much of sendBuf has been sent so far (partial-send handling)

		PerIoData recvIo;
		PerIoData sendIo;

		// outstanding WSARecv/WSASend calls on this socket; the context is only
		// actually freed once this drops to zero after a close was requested,
		// so we never touch a ClientContext a completion packet still points to
		std::atomic<int> pendingOps{ 0 };
		bool closing = false;

		ClientContext() {
			recvIo.op = IoOperation::Recv;
			recvIo.owner = this;
			recvIo.wsaBuf.buf = recvChunk.data();
			recvIo.wsaBuf.len = static_cast<ULONG>(recvChunk.size());

			sendIo.op = IoOperation::Send;
			sendIo.owner = this;
		}
	};

	struct AcceptContext {
		PerIoData io;
		SOCKET acceptSocket = INVALID_SOCKET;
		// GetAcceptExSockaddrs wants buffers 16 bytes larger than the address
		// structure on each side, per AcceptEx's documented contract
		std::array<char, 2 * (sizeof(sockaddr_in) + 16)> addrBuf{};

		AcceptContext() { io.op = IoOperation::Accept; io.owner = this; }
	};


	LPFN_ACCEPTEX g_acceptEx = nullptr;
	LPFN_GETACCEPTEXSOCKADDRS g_getAcceptExSockaddrs = nullptr;
	HANDLE g_ioPort = nullptr;
	SOCKET g_listenSocket = INVALID_SOCKET;


	[[nodiscard]] std::string ipOf(const ClientContext& c) {
		char buf[INET_ADDRSTRLEN]{};
		inet_ntop(AF_INET, &c.remoteAddr.sin_addr, buf, sizeof(buf));
		return std::format("{}:{}", buf, ntohs(c.remoteAddr.sin_port));
	}

	[[nodiscard]] const char* requestTypeName(RequestType t) {
		switch (t) {
		case RequestType::Empty:     return "Empty";
		case RequestType::OS:        return "OS";
		case RequestType::SystemTime:return "SystemTime";
		case RequestType::Uptime:    return "Uptime";
		case RequestType::Memory:    return "Memory";
		case RequestType::Disks:     return "Disks";
		case RequestType::FreeSpace: return "FreeSpace";
		case RequestType::ACEFile:   return "ACEFile";
		case RequestType::ACEReg:    return "ACEReg";
		case RequestType::OwnerFile: return "OwnerFile";
		case RequestType::OwnerReg:  return "OwnerReg";
		}
		return "<unknown>";
	}


	void postRecv(ClientContext* client) {
		if (client->closing) return;

		ZeroMemory(&client->recvIo.overlapped, sizeof(OVERLAPPED));
		client->recvIo.wsaBuf.buf = client->recvChunk.data();
		client->recvIo.wsaBuf.len = static_cast<ULONG>(client->recvChunk.size());

		DWORD flags = 0;
		client->pendingOps.fetch_add(1);

		const int rc = WSARecv(client->socket, &client->recvIo.wsaBuf, 1, nullptr,
			&flags, &client->recvIo.overlapped, nullptr);

		if (rc == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
			client->pendingOps.fetch_sub(1);
			client->closing = true;
		}
	}

	// (re)issues WSASend starting at client->sendOffset, for the data already
	// sitting in client->sendBuf (used both for the first send and to push the
	// remainder of a partial send)
	void postSend(ClientContext* client) {
		if (client->closing) return;

		ZeroMemory(&client->sendIo.overlapped, sizeof(OVERLAPPED));
		client->sendIo.wsaBuf.buf = reinterpret_cast<char*>(client->sendBuf.data()) + client->sendOffset;
		client->sendIo.wsaBuf.len = static_cast<ULONG>(client->sendBuf.size() - client->sendOffset);

		client->pendingOps.fetch_add(1);

		const int rc = WSASend(client->socket, &client->sendIo.wsaBuf, 1, nullptr, 0,
			&client->sendIo.overlapped, nullptr);

		if (rc == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
			client->pendingOps.fetch_sub(1);
			client->closing = true;
		}
	}

	// encrypts/frames nothing by itself --- `msg` is the already-assembled
	// [MessageType][...] body; this just prepends the 4-byte length and starts sending
	void sendFrame(ClientContext* client, std::vector<uint8_t> msg) {
		client->sendBuf.clear();
		client->sendOffset = 0;

		const uint32_t beLen = htonl(static_cast<uint32_t>(msg.size()));
		const auto* lenBytes = reinterpret_cast<const uint8_t*>(&beLen);
		client->sendBuf.insert(client->sendBuf.end(), lenBytes, lenBytes + 4);
		client->sendBuf.insert(client->sendBuf.end(), msg.begin(), msg.end());

		postSend(client);
	}

	void postAccept(AcceptContext* actx);

	void maybeDestroy(ClientContext* client) {
		if (client->closing && client->pendingOps.load() == 0) {
			std::println("[-] Client disconnected: {}", ipOf(*client));
			if (client->socket != INVALID_SOCKET) closesocket(client->socket);
			delete client;
		}
	}

	void beginClose(ClientContext* client) {
		if (client->closing) {
			maybeDestroy(client);
			return;
		}
		client->closing = true;
		if (client->socket != INVALID_SOCKET) {
			CancelIoEx(reinterpret_cast<HANDLE>(client->socket), nullptr);
		}
		maybeDestroy(client); // in case there were zero pending ops already
	}


	void handleHandshake(ClientContext* client, std::span<const uint8_t> clientPublicBlob) {
		auto own = crypto::EcdhKeyPair::generate();
		if (!own) {
			std::println(stderr, "FAIL: couldn't generate ECDH key pair for {}", ipOf(*client));
			beginClose(client);
			return;
		}

		auto aesKey = own->deriveAesKey(clientPublicBlob);
		if (!aesKey) {
			std::println(stderr, "FAIL: couldn't derive session key for {}", ipOf(*client));
			beginClose(client);
			return;
		}

		auto ourPub = own->exportPublicBlob();
		if (!ourPub) {
			beginClose(client);
			return;
		}

		client->aesKey = std::move(*aesKey);
		client->state = ClientContext::State::Ready;

		std::vector<uint8_t> msg;
		msg.reserve(1 + ourPub->size());
		msg.push_back(static_cast<uint8_t>(MessageType::HandshakeResponse));
		msg.insert(msg.end(), ourPub->begin(), ourPub->end());
		sendFrame(client, std::move(msg));

		std::println("[i] Session key established with {}", ipOf(*client));
	}


	void handleRequest(ClientContext* client, std::span<const uint8_t> encryptedBody) {
		auto plain = crypto::aesGcmDecrypt(client->aesKey.get(), encryptedBody);
		if (!plain) {
			std::println(stderr, "FAIL: decryption failed for {} (corrupted frame or tampering)", ipOf(*client));
			beginClose(client);
			return;
		}

		auto reqResult = proto::deserializeRequest(*plain);

		ReturnCode rc = ReturnCode::UnexpectedError;
		std::vector<uint8_t> payload;

		if (!reqResult) {
			rc = reqResult.error();
		}
		else {
			const request& req = *reqResult;
			std::println("[>] {} requested {}", ipOf(*client), requestTypeName(req.type));

			switch (req.type) {
			case RequestType::OS: {
				auto r = gatherOSInfo();
				if (r) { payload = proto::serialize(*r); rc = ReturnCode::Success; }
				else rc = r.error();
				break;
			}
			case RequestType::SystemTime: {
				auto r = gatherUnixTime();
				if (r) { payload = proto::serialize(*r); rc = ReturnCode::Success; }
				else rc = r.error();
				break;
			}
			case RequestType::Uptime: {
				auto r = gatherUptime();
				if (r) { payload = proto::serialize(*r); rc = ReturnCode::Success; }
				else rc = r.error();
				break;
			}
			case RequestType::Memory: {
				auto r = gatherMemoryInfo();
				if (r) { payload = proto::serialize(*r); rc = ReturnCode::Success; }
				else rc = r.error();
				break;
			}
			case RequestType::Disks: {
				auto r = gatherDisksInfo();
				if (r) { payload = proto::serialize(*r); rc = ReturnCode::Success; }
				else rc = r.error();
				break;
			}
			case RequestType::FreeSpace: {
				auto r = gatherFreeSpaceInfo();
				if (r) { payload = proto::serialize(*r); rc = ReturnCode::Success; }
				else rc = r.error();
				break;
			}
			case RequestType::ACEFile:
			case RequestType::ACEReg: {
				auto r = gatherACEInfo(req);
				if (r) { payload = proto::serialize(*r); rc = ReturnCode::Success; }
				else rc = r.error();

				// clean up the SIDs gatherACEInfo() allocated for us now that
				// they've been copied into the wire payload
				if (r) for (const auto& ace : *r) if (ace.subjectSID) LocalFree(ace.subjectSID);
				break;
			}
			case RequestType::OwnerFile:
			case RequestType::OwnerReg: {
				auto r = gatherOwnerInfo(req);
				if (r) { payload = proto::serialize(*r); rc = ReturnCode::Success; }
				else rc = r.error();

				if (r) for (const auto& o : *r) if (o.ownerSID) LocalFree(o.ownerSID);
				break;
			}
			case RequestType::Empty:
			default:
				rc = ReturnCode::InvalidValue;
				break;
			}
		}

		proto::ByteWriter w;
		w.u8(static_cast<uint8_t>(rc));
		auto respPlain = w.take();
		respPlain.insert(respPlain.end(), payload.begin(), payload.end());

		auto encrypted = crypto::aesGcmEncrypt(client->aesKey.get(), respPlain);
		if (!encrypted) {
			beginClose(client);
			return;
		}

		std::vector<uint8_t> msg;
		msg.reserve(1 + encrypted->size());
		msg.push_back(static_cast<uint8_t>(MessageType::Response));
		msg.insert(msg.end(), encrypted->begin(), encrypted->end());
		sendFrame(client, std::move(msg));

		std::println("[<] Responded to {} ({})", ipOf(*client),
			rc == ReturnCode::Success ? "OK" : "ERROR");
	}


	void handleFrame(ClientContext* client, std::span<const uint8_t> payload) {
		if (payload.empty()) {
			std::println(stderr, "WARN: empty frame from {}", ipOf(*client));
			beginClose(client);
			return;
		}

		const auto msgType = static_cast<MessageType>(payload[0]);
		const auto body = payload.subspan(1);

		if (client->state == ClientContext::State::AwaitingHandshake) {
			if (msgType != MessageType::HandshakeInit) {
				std::println(stderr, "WARN: {} sent a non-handshake message before handshake", ipOf(*client));
				beginClose(client);
				return;
			}
			handleHandshake(client, body);
			return;
		}

		if (msgType != MessageType::Request) {
			std::println(stderr, "WARN: {} sent an unexpected message type after handshake", ipOf(*client));
			beginClose(client);
			return;
		}
		handleRequest(client, body);
	}


	// pulls as many complete [len][payload] frames as are currently buffered
	// out of client->recvAccum and dispatches each one
	void drainFrames(ClientContext* client) {
		for (;;) {
			if (client->recvAccum.size() < 4) return;

			uint32_t beLen;
			std::memcpy(&beLen, client->recvAccum.data(), 4);
			const uint32_t frameLen = ntohl(beLen);

			if (frameLen > MAX_FRAME_BYTES) {
				std::println(stderr, "WARN: {} sent an oversized frame ({} bytes), closing", ipOf(*client), frameLen);
				beginClose(client);
				return;
			}

			if (client->recvAccum.size() < 4u + frameLen) return; // wait for more data

			const std::span<const uint8_t> payload{ client->recvAccum.data() + 4, frameLen };
			handleFrame(client, payload);

			if (client->closing) return;

			client->recvAccum.erase(client->recvAccum.begin(), client->recvAccum.begin() + 4 + frameLen);
		}
	}


	void onAcceptCompletion(AcceptContext* actx, bool ok) {
		if (ok) {
			setsockopt(actx->acceptSocket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
				reinterpret_cast<char*>(&g_listenSocket), sizeof(g_listenSocket));

			sockaddr_in* localAddr = nullptr;
			sockaddr_in* remoteAddr = nullptr;
			int localLen = 0, remoteLen = 0;

			g_getAcceptExSockaddrs(
				actx->addrBuf.data(), 0,
				sizeof(sockaddr_in) + 16, sizeof(sockaddr_in) + 16,
				reinterpret_cast<sockaddr**>(&localAddr), &localLen,
				reinterpret_cast<sockaddr**>(&remoteAddr), &remoteLen);

			auto* client = new ClientContext();
			client->socket = actx->acceptSocket;
			if (remoteAddr) client->remoteAddr = *remoteAddr;

			std::println("[+] Client connected: {}", ipOf(*client));

			if (CreateIoCompletionPort(reinterpret_cast<HANDLE>(client->socket), g_ioPort, 0, 0) == nullptr) {
				std::println(stderr, "FAIL: CreateIoCompletionPort for new client failed (code {})", GetLastError());
				closesocket(client->socket);
				delete client;
			}
			else {
				postRecv(client);
			}

			actx->acceptSocket = INVALID_SOCKET;
		}
		else {
			std::println(stderr, "WARN: AcceptEx completion failed (code {})", GetLastError());
			if (actx->acceptSocket != INVALID_SOCKET) {
				closesocket(actx->acceptSocket);
				actx->acceptSocket = INVALID_SOCKET;
			}
		}

		postAccept(actx); // always keep exactly one accept pending
	}

	void postAccept(AcceptContext* actx) {
		actx->acceptSocket = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
		if (actx->acceptSocket == INVALID_SOCKET) {
			std::println(stderr, "FAIL: WSASocketW (accept socket) failed (code {})", WSAGetLastError());
			return;
		}

		ZeroMemory(&actx->io.overlapped, sizeof(OVERLAPPED));

		DWORD bytesReceived = 0;
		const BOOL ok = g_acceptEx(
			g_listenSocket, actx->acceptSocket,
			actx->addrBuf.data(), 0,
			sizeof(sockaddr_in) + 16, sizeof(sockaddr_in) + 16,
			&bytesReceived, &actx->io.overlapped);

		if (!ok && WSAGetLastError() != ERROR_IO_PENDING) {
			std::println(stderr, "FAIL: AcceptEx failed to start (code {})", WSAGetLastError());
			closesocket(actx->acceptSocket);
			actx->acceptSocket = INVALID_SOCKET;
		}
	}


	[[nodiscard]] bool loadAcceptExFunctions() {
		GUID guidAcceptEx = WSAID_ACCEPTEX;
		GUID guidGetAcceptExSockaddrs = WSAID_GETACCEPTEXSOCKADDRS;
		DWORD bytes = 0;

		if (WSAIoctl(g_listenSocket, SIO_GET_EXTENSION_FUNCTION_POINTER,
			&guidAcceptEx, sizeof(guidAcceptEx),
			&g_acceptEx, sizeof(g_acceptEx), &bytes, nullptr, nullptr) == SOCKET_ERROR)
		{
			std::println(stderr, "FAIL: couldn't resolve AcceptEx (code {})", WSAGetLastError());
			return false;
		}

		if (WSAIoctl(g_listenSocket, SIO_GET_EXTENSION_FUNCTION_POINTER,
			&guidGetAcceptExSockaddrs, sizeof(guidGetAcceptExSockaddrs),
			&g_getAcceptExSockaddrs, sizeof(g_getAcceptExSockaddrs), &bytes, nullptr, nullptr) == SOCKET_ERROR)
		{
			std::println(stderr, "FAIL: couldn't resolve GetAcceptExSockaddrs (code {})", WSAGetLastError());
			return false;
		}

		return true;
	}


	void workerLoop() {
		for (;;) {
			DWORD transferred = 0;
			ULONG_PTR key = 0;
			OVERLAPPED* overlapped = nullptr;

			const BOOL ok = GetQueuedCompletionStatus(g_ioPort, &transferred, &key, &overlapped, INFINITE);

			if (overlapped == nullptr) {
				// only happens if the IOCP handle itself was closed/invalid;
				// treat as a signal to shut this worker down
				return;
			}

			auto* io = reinterpret_cast<PerIoData*>(overlapped);

			switch (io->op) {
			case IoOperation::Accept: {
				onAcceptCompletion(static_cast<AcceptContext*>(io->owner), ok != FALSE);
				break;
			}
			case IoOperation::Recv: {
				auto* client = static_cast<ClientContext*>(io->owner);
				client->pendingOps.fetch_sub(1);

				if (!ok || transferred == 0) {
					beginClose(client);
					break;
				}

				client->recvAccum.insert(client->recvAccum.end(),
					client->recvChunk.data(), client->recvChunk.data() + transferred);

				drainFrames(client);

				if (!client->closing) postRecv(client);
				maybeDestroy(client);
				break;
			}
			case IoOperation::Send: {
				auto* client = static_cast<ClientContext*>(io->owner);
				client->pendingOps.fetch_sub(1);

				if (!ok || transferred == 0) {
					beginClose(client);
					break;
				}

				client->sendOffset += transferred;
				if (client->sendOffset < client->sendBuf.size()) {
					postSend(client); // partial send --- push the remainder
				}

				maybeDestroy(client);
				break;
			}
			}
		}
	}

} // anonymous namespace


bool runServer(uint16_t port) {
	WSADATA wsaData{};
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::println(stderr, "FAIL: WSAStartup failed");
		return false;
	}

	g_listenSocket = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
	if (g_listenSocket == INVALID_SOCKET) {
		std::println(stderr, "FAIL: WSASocketW (listen socket) failed (code {})", WSAGetLastError());
		return false;
	}

	if (!loadAcceptExFunctions()) {
		return false;
	}

	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	if (bind(g_listenSocket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
		std::println(stderr, "FAIL: bind() failed (code {})", WSAGetLastError());
		return false;
	}

	if (listen(g_listenSocket, SOMAXCONN) == SOCKET_ERROR) {
		std::println(stderr, "FAIL: listen() failed (code {})", WSAGetLastError());
		return false;
	}

	g_ioPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);
	if (g_ioPort == nullptr) {
		std::println(stderr, "FAIL: CreateIoCompletionPort failed (code {})", GetLastError());
		return false;
	}

	if (CreateIoCompletionPort(reinterpret_cast<HANDLE>(g_listenSocket), g_ioPort, 0, 0) == nullptr) {
		std::println(stderr, "FAIL: CreateIoCompletionPort (listen socket) failed (code {})", GetLastError());
		return false;
	}

	std::println("Listening on port {}", port);

	auto* acceptCtx = new AcceptContext();
	postAccept(acceptCtx);

	const unsigned hwThreads = std::thread::hardware_concurrency();
	const unsigned workerCount = hwThreads > 0 ? hwThreads : 2;

	std::vector<std::jthread> workers;
	workers.reserve(workerCount - 1);
	for (unsigned i = 1; i < workerCount; i++) {
		workers.emplace_back([] { workerLoop(); });
	}

	// the calling thread also serves as a worker, so the process has
	// `workerCount` IOCP workers in total
	workerLoop();

	// workerLoop() only returns if the IOCP handle is closed/invalid, which
	// currently only happens at process exit; workers[] joins automatically
	// via std::jthread's destructor
	return true;
}
