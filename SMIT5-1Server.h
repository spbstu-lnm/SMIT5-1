/******************************************************************************

	SMIT5-1Server.h: IOCP-based network server entry point

******************************************************************************/

#pragma once

#include <cstdint>

// Starts listening on `port` and serves requests forever using a pool of
// worker threads reading from a single IO completion port. Blocks the
// calling thread (joins the worker pool). Returns false if the server
// couldn't even start (bind/listen/IOCP setup failure).
[[nodiscard]] bool runServer(uint16_t port);
