/******************************************************************************

	SMIT5-1Client.h : client-side include file

	Mirrors the include/link setup of the server's SMIT5-1.h. The one
	addition is <Sddl.h>, for ConvertSidToStringSidW() -- the client needs
	it to print the SIDs it receives from the server (see SMIT5-1Display.h),
	the server never needed it because it never prints a SID, only resolves
	it to an account name.

	NOTES:
		- NOMINMAX / WIN32_LEAN_AND_MEAN: same convention as the server,
			define them in the project settings / CMakeLists.txt rather
			than here

		- the client is a plain console app using blocking sockets: unlike
			the server it only ever talks to one peer at a time, so there
			is no need for IO Completion Ports here (the lab's IOCP
			requirement is explicitly a SERVER requirement)

******************************************************************************/

#pragma once


#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <ctime>

#include <expected>
#include <print>
#include <format>
#include <memory>
#include <utility>
#include <string>
#include <vector>
#include <span>

#include <iostream>

#include <WinSock2.h>
#include <Windows.h>
#include <WS2tcpip.h>

#include <bcrypt.h>
#include <Sddl.h>		// ADDED --- ConvertSidToStringSidW, for displaying SIDs


#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")	// ADDED --- ConvertSidToStringSidW
