#pragma once

#include <afxdp_helper.h>
#include <afxdp_experimental.h>
#include <xdpapi.h>

#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include "OLSHighPerfTimer.h"

#include <winsock2.h>
#include <netiodef.h>
#include <string>
#include <vector>
#include <ws2ipdef.h>

#pragma warning(disable:4200) // nonstandard extension used: zero-sized array in struct/union

#define SHALLOW_STR_OF(x) #x
#define STR_OF(x) SHALLOW_STR_OF(x)

#define ALIGN_DOWN_BY(length, alignment) \
    ((ULONG_PTR)(length)& ~(alignment - 1))
#define ALIGN_UP_BY(length, alignment) \
    (ALIGN_DOWN_BY(((ULONG_PTR)(length)+alignment - 1), alignment))

#define STRUCT_FIELD_OFFSET(structPtr, field) \
    ((UCHAR *)&(structPtr)->field - (UCHAR *)(structPtr))

#define DEFAULT_UMEM_SIZE 65536
#define DEFAULT_UMEM_CHUNK_SIZE 4096
#define DEFAULT_UMEM_HEADROOM 0
#define DEFAULT_IO_BATCH 1
#define DEFAULT_NODE_AFFINITY -1
#define DEFAULT_GROUP -1
#define DEFAULT_IDEAL_CPU -1
#define DEFAULT_CPU_AFFINITY 0
#define DEFAULT_UDP_DEST_PORT 0
#define DEFAULT_DURATION ULONG_MAX
#define DEFAULT_TX_IO_SIZE 64
#define DEFAULT_LAT_COUNT 10000000
#define DEFAULT_YIELD_COUNT 0

//huajianwang:eelat
#define DEFAULT_REQ_BATCH 1
#define DEFAULT_ACK_BATCH 1
#define DEFAULT_WAIT_BATCH 1
#define DEFAULT_REQ_RATE 0
#define DEFAULT_FRAME_RATE 10000
#define DEFAULT_REQ_SAMPLES 2000000
//-huajianwang:eelat

#define printf_error(...) \
    fprintf(stderr, __VA_ARGS__)

#define printf_verbose(format, ...) \
    if (verbose) { LARGE_INTEGER Qpc; QueryPerformanceCounter(&Qpc); printf("Qpc=%llu " format, Qpc.QuadPart, __VA_ARGS__); }

#define ABORT(...) \
    printf_error(__VA_ARGS__); exit(1)

#define ASSERT_FRE(expr) \
    if (!(expr)) { ABORT("(%s) failed line %d\n", #expr, __LINE__);}

#if DBG
#define VERIFY(expr) assert(expr)
#else
#define VERIFY(expr) (expr)
#endif

#define Usage() PrintUsage(__LINE__)

#define WAIT_DRIVER_TIMEOUT_MS 1050
#define STATS_ARRAY_SIZE 60

INT64
QpcToUs64(
    INT64 Qpc,
    INT64 QpcFrequency
);
