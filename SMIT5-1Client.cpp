/******************************************************************************

	SMIT5-1Client.cpp : console client --- entry point

	C++23

	client half of the SMIT5-1 distributed PC info collection system

	UI implemented in this file:
		- setting the server address
		- selecting the request type
		- initiating the request
		- displaying the information the server sent back

	two types of functions other than main:

		- handleXxxRequest(conn, ...)

		- promptXxx()/buildRequest()

******************************************************************************/

#include "SMIT5-1Client.h"
#include "SMIT5-1Shared.h"
#include "SMIT5-1Protocol.h"
#include "SMIT5-1ClientNet.h"
#include "SMIT5-1Display.h"
#include <fcntl.h>
#include <io.h>
#include <limits>
#include <stdexcept>


// CONSTANTS	===============================================================
inline constexpr uint16_t DEFAULT_SERVER_PORT = 9000; // matches SERVER_PORT in the server's SMIT5-1.cpp


// PROTOTYPES	===============================================================

// --- UI-specific input helpers
[[nodiscard]] static std::wstring promptServerAddress();
[[nodiscard]] static uint16_t promptServerPort();
[[nodiscard]] static RequestType promptRequestType(); // returns RequestType::Empty to mean "quit"
[[nodiscard]] static request buildRequest(RequestType type);

// --- request handlers, one per RequestType
static void printMenu();
static void configureConsoleIO();
static void handleOSRequest(ServerConnection& conn);
static void handleSystemTimeRequest(ServerConnection& conn);
static void handleUptimeRequest(ServerConnection& conn);
static void handleMemoryRequest(ServerConnection& conn);
static void handleDisksRequest(ServerConnection& conn);
static void handleFreeSpaceRequest(ServerConnection& conn);
static void handleACERequest(ServerConnection& conn, RequestType type);   // ACEFile or ACEReg
static void handleOwnerRequest(ServerConnection& conn, RequestType type); // OwnerFile or OwnerReg


// FUNCTIONS	===============================================================

int main() {
	// switch to UTF-16 to allow printing cyrillic characters
	configureConsoleIO();

	WSADATA wsaData{};
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::println(stderr, "FAIL: WSAStartup failed");
		return EXIT_FAILURE;
	}

	const int result = [&]() {
		const auto host = promptServerAddress();
		const auto port = promptServerPort();

		auto connResult = ServerConnection::connectTo(host, port);
		if (!connResult) {
			std::println(stderr, "FAIL: couldn't connect to / handshake with the server");
			return EXIT_FAILURE;
		}
		ServerConnection conn = std::move(*connResult);
		std::wcout << L"Connected, session key established.\n";

		for (;;) {
			printMenu();
			const RequestType type = promptRequestType();
			if (type == RequestType::Empty) break; // "0" / quit

			switch (type) {
			case RequestType::OS:         handleOSRequest(conn); break;
			case RequestType::SystemTime: handleSystemTimeRequest(conn); break;
			case RequestType::Uptime:     handleUptimeRequest(conn); break;
			case RequestType::Memory:     handleMemoryRequest(conn); break;
			case RequestType::Disks:      handleDisksRequest(conn); break;
			case RequestType::FreeSpace:  handleFreeSpaceRequest(conn); break;
			case RequestType::ACEFile:
			case RequestType::ACEReg:     handleACERequest(conn, type); break;
			case RequestType::OwnerFile:
			case RequestType::OwnerReg:   handleOwnerRequest(conn, type); break;
			default:
				std::println(stderr, "Unhandled request type, try again");
				break;
			}
		}
		return EXIT_SUCCESS;
	}();

	// destroy the connection (and close its socket) before Winsock cleanup
	WSACleanup();
	return result;
}


static void configureConsoleIO() {
	DWORD consoleMode = 0;
	if (GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &consoleMode)) {
		_setmode(_fileno(stdin), _O_U16TEXT);
	}
	if (GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &consoleMode)) {
		_setmode(_fileno(stdout), _O_U16TEXT);
	}
}


static void printMenu() {
	std::wcout << L"\n--- SMIT5-1 client ---\n"
		<< L" 1) OS version            2) System time           3) Uptime\n"
		<< L" 4) Memory                5) Disks                 6) Free space\n"
		<< L" 7) Access rights (file)  8) Access rights (registry key)\n"
		<< L" 9) Owner (file)         10) Owner (registry key)\n"
		<< L" 0) Quit\n";
}


// ---- request handlers ------------------------------------------------------
// build request -> send -> deserialize -> display.

static void handleOSRequest(ServerConnection& conn) {
	auto payload = conn.sendRequest(request{ .type = RequestType::OS });
	if (!payload) { std::println(stderr, "FAIL: server returned an error"); return; }

	auto info = proto::deserializeOSInfo(*payload);
	if (!info) { std::println(stderr, "FAIL: malformed OS info in response"); return; }

	display::printOSInfo(*info);
}

static void handleSystemTimeRequest(ServerConnection& conn) {
	auto payload = conn.sendRequest(request{ .type = RequestType::SystemTime });
	if (!payload) { std::println(stderr, "FAIL: server returned an error"); return; }

	auto info = proto::deserializeSystemTime(*payload);
	if (!info) { std::println(stderr, "FAIL: malformed system time in response"); return; }

	display::printSystemTime(*info);
}

static void handleUptimeRequest(ServerConnection& conn) {
	auto payload = conn.sendRequest(request{ .type = RequestType::Uptime });
	if (!payload) { std::println(stderr, "FAIL: server returned an error"); return; }

	auto info = proto::deserializeUptime(*payload);
	if (!info) { std::println(stderr, "FAIL: malformed uptime in response"); return; }

	display::printUptime(*info);
}

static void handleMemoryRequest(ServerConnection& conn) {
	auto payload = conn.sendRequest(request{ .type = RequestType::Memory });
	if (!payload) { std::println(stderr, "FAIL: server returned an error"); return; }

	auto info = proto::deserializeMemoryInfo(*payload);
	if (!info) { std::println(stderr, "FAIL: malformed memory info in response"); return; }

	display::printMemoryInfo(*info);
}

static void handleDisksRequest(ServerConnection& conn) {
	auto payload = conn.sendRequest(request{ .type = RequestType::Disks });
	if (!payload) { std::println(stderr, "FAIL: server returned an error"); return; }

	auto info = proto::deserializeDisksInfo(*payload);
	if (!info) { std::println(stderr, "FAIL: malformed disks info in response"); return; }

	display::printDisksInfo(*info);
}

static void handleFreeSpaceRequest(ServerConnection& conn) {
	auto payload = conn.sendRequest(request{ .type = RequestType::FreeSpace });
	if (!payload) { std::println(stderr, "FAIL: server returned an error"); return; }

	auto info = proto::deserializeFreeSpaceInfo(*payload);
	if (!info) { std::println(stderr, "FAIL: malformed free space info in response"); return; }

	display::printFreeSpaceInfo(*info);
}

static void handleACERequest(ServerConnection& conn, RequestType type) {
	const request req = buildRequest(type);

	auto payload = conn.sendRequest(req);
	if (!payload) { std::println(stderr, "FAIL: server returned an error"); return; }

	auto aces = proto::deserializeACEList(*payload);
	if (!aces) { std::println(stderr, "FAIL: malformed ACE list in response"); return; }

	const auto kind = (type == RequestType::ACEFile) ? display::ObjectKind::File : display::ObjectKind::Registry;
	display::printACEList(*aces, kind);
}

static void handleOwnerRequest(ServerConnection& conn, RequestType type) {
	const request req = buildRequest(type);

	auto payload = conn.sendRequest(req);
	if (!payload) { std::println(stderr, "FAIL: server returned an error"); return; }

	auto owners = proto::deserializeOwnerList(*payload);
	if (!owners) { std::println(stderr, "FAIL: malformed owner info in response"); return; }

	display::printOwnerList(*owners);
}


// ---- UI-specific console input ---------------------------------------------

static std::wstring promptServerAddress() {
	for (;;) {
		std::wcout << L"Server address [127.0.0.1]: ";
		std::wstring address;
		if (!std::getline(std::wcin, address)) return L"127.0.0.1";
		if (address.empty()) return L"127.0.0.1";
		return address;
	}
}

static uint16_t promptServerPort() {
	for (;;) {
		std::wcout << L"Server port [" << DEFAULT_SERVER_PORT << L"]: ";
		std::wstring line;
		if (!std::getline(std::wcin, line) || line.empty()) return DEFAULT_SERVER_PORT;
		try {
			size_t consumed = 0;
			const unsigned long value = std::stoul(line, &consumed);
			if (consumed == line.size() && value > 0 && value <= std::numeric_limits<uint16_t>::max())
				return static_cast<uint16_t>(value);
		} catch (const std::exception&) {}
		std::wcout << L"Enter a port from 1 to 65535.\n";
	}
}

static RequestType promptRequestType() {
	for (;;) {
		std::wcout << L"Select request (0-10): ";
		std::wstring line;
		if (!std::getline(std::wcin, line)) return RequestType::Empty;
		std::wcout << L"\n";
		try {
			size_t consumed = 0;
			const unsigned long choice = std::stoul(line, &consumed);
			if (consumed != line.size() || choice > 10) throw std::invalid_argument("choice");
			static constexpr RequestType choices[] = {
				RequestType::Empty, RequestType::OS, RequestType::SystemTime,
				RequestType::Uptime, RequestType::Memory, RequestType::Disks,
				RequestType::FreeSpace, RequestType::ACEFile, RequestType::ACEReg,
				RequestType::OwnerFile, RequestType::OwnerReg
			};
			return choices[choice];
		} catch (const std::exception&) {
			std::wcout << L"Invalid choice. Enter a number from 0 to 10.\n\n";
		}
	}
}

//   - for RequestType::ACEFile / OwnerFile: prompt a filesystem path
//	   and put it in req.path.
//   - for RequestType::ACEReg / OwnerReg: prompt a choice among the five
//     predefined roots accepted by isAllowedPredefinedRoot() in
//     SMIT5-1Shared.h req.hRootKey, 
//     and a subkey path (e.g. L"SOFTWARE") for req.path.
// the server re-validates hRootKey against the same whitelist regardless,
// so the only thing a wrong value here costs is an InvalidValue response.
static request buildRequest(RequestType type) {
	request req{ .type = type };
	if (type == RequestType::ACEFile || type == RequestType::OwnerFile) {
		std::wcout << L"File or directory path: ";
		std::getline(std::wcin, req.path);
		std::wcout << L"\n";
		return req;
	}

	if (type == RequestType::ACEReg || type == RequestType::OwnerReg) {
		static const HKEY roots[] = {
			HKEY_CLASSES_ROOT, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE,
			HKEY_USERS, HKEY_CURRENT_CONFIG
		};
		static constexpr const wchar_t* names[] = {
			L"HKEY_CLASSES_ROOT", L"HKEY_CURRENT_USER", L"HKEY_LOCAL_MACHINE",
			L"HKEY_USERS", L"HKEY_CURRENT_CONFIG"
		};
		for (;;) {
			std::wcout << L"Registry root:\n";
			for (size_t i = 0; i < std::size(roots); ++i)
				std::wcout << L" " << (i + 1) << L") " << names[i] << L'\n';
			std::wcout << L"Select root (1-5): ";
			std::wstring line;
			if (!std::getline(std::wcin, line)) return req;
			std::wcout << L"\n";
			try {
				size_t consumed = 0;
				const unsigned long choice = std::stoul(line, &consumed);
				if (consumed == line.size() && choice >= 1 && choice <= std::size(roots)) {
					req.hRootKey = roots[choice - 1];
					break;
				}
			} catch (const std::exception&) {}
			std::wcout << L"Invalid root choice.\n";
		}
		std::wcout << L"Registry subkey path (empty for root): ";
		std::getline(std::wcin, req.path);
		std::wcout << L"\n";
	}
	return req;
}
