//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

#pragma once

#include "netport.h"

#define DEFAULT_UDP_DEST_PORT 0

extern BOOLEAN logVerbose;
extern BOOLEAN largePages;
extern UINT16 udpDestPort;

void PrintPacketMeta(_In_ void* buffer);
bool parseAddress(const char* input, char* ip_out, int& port_out);
