#pragma once

#pragma warning(disable:4200) // nonstandard extension used: zero-sized array in struct/union

/*
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

#define DEFAULT_PAYLOAD_SIZE 64
//huajianwang:eelat
#define DEFAULT_FRAMES_PER_FILE 1
#define DEFAULT_FILE_RATE 0
#define DEFAULT_FRAME_RATE 10000
//-huajianwang:eelat
*/

#define Usage() PrintUsage(__LINE__)

#include "internal_utils.h"
#include "rss_queue.h"


typedef struct {
    HANDLE threadHandle;
    HANDLE readyEvent;
    LONG nodeAffinity;
    LONG group;
    LONG idealCpu;
    UINT32 yieldCount;
    DWORD_PTR cpuAffinity;
    BOOLEAN wait;

    UINT32 queueCount;
    RssQueue* queues;
} NetThread;

