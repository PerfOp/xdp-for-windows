//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

#pragma once

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

void GetMACAddress(
    _In_ DWORD ifIndex,
    _Out_ char* macAddr,
    _In_ size_t macAddrSize
);

void GetIPAddress(
    _In_ DWORD ifIndex,
    _Out_ char* ipAddr, 
    _In_ size_t ipAddrSize
);
bool InitAdapter(_In_ DWORD ifIndex);

void FindAdapterByIP(
    _In_ const char* targetIP, 
    _Out_ VOID* pInfo);

#ifdef __cplusplus
} // extern "C"
#endif
