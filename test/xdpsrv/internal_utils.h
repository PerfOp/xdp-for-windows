//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

#pragma once

#define SHALLOW_STR_OF(x) #x
#define STR_OF(x) SHALLOW_STR_OF(x)

#define ALIGN_DOWN_BY(length, alignment) \
    ((ULONG_PTR)(length)& ~(alignment - 1))
#define ALIGN_UP_BY(length, alignment) \
    (ALIGN_DOWN_BY(((ULONG_PTR)(length)+alignment - 1), alignment))

#define STRUCT_FIELD_OFFSET(structPtr, field) \
    ((UCHAR *)&(structPtr)->field - (UCHAR *)(structPtr))

#define printf_error(...) \
    fprintf(stderr, __VA_ARGS__)

#define printf_verbose(format, ...) \
    if (logVerbose) { LARGE_INTEGER Qpc; QueryPerformanceCounter(&Qpc); printf("Qpc=%llu " format, Qpc.QuadPart, __VA_ARGS__); }

#define ABORT(...) \
    printf_error(__VA_ARGS__); exit(1)

#define ASSERT_FRE(expr) \
    if (!(expr)) { ABORT("(%s) failed line %d\n", #expr, __LINE__);}

#if DBG
#define VERIFY(expr) assert(expr)
#else
#define VERIFY(expr) (expr)
#endif

#define DEFAULT_UDP_DEST_PORT 0

extern BOOLEAN logVerbose;
extern BOOLEAN largePages;
extern UINT16 udpDestPort;

/*
INT64
QpcToUs64(
    INT64 Qpc,
    INT64 QpcFrequency
);
*/
void PrintPacketMeta(_In_ void* buffer);
bool parseAddress(const char* input, char* ip_out, int& port_out);
