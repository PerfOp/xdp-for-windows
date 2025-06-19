//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

#pragma once

#include <afxdp_helper.h>
#include <afxdp_experimental.h>
#include <xdpapi.h>

#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>

#define DEFAULT_UMEM_SIZE 65536
#define DEFAULT_UMEM_CHUNK_SIZE 4096
#define DEFAULT_UMEM_HEADROOM 0
#define DEFAULT_IO_BATCH 1
#define DEFAULT_NODE_AFFINITY -1
#define DEFAULT_GROUP -1
#define DEFAULT_IDEAL_CPU -1
#define DEFAULT_CPU_AFFINITY 0
#define DEFAULT_DURATION ULONG_MAX
#define DEFAULT_TX_IO_SIZE 64
#define DEFAULT_LAT_COUNT 10000000
#define DEFAULT_YIELD_COUNT 0

#define DEFAULT_PAYLOAD_SIZE 64
//huajianwang:eelat
const uint64_t DEFAULT_REQ_PPS = 0;
#define DEFAULT_FRAMES_PER_FILE 1
#define DEFAULT_FILE_RATE 0
#define DEFAULT_FRAME_RATE 10000
//-huajianwang:eelat

#define WAIT_DRIVER_TIMEOUT_MS 1050
#define STATS_ARRAY_SIZE 60
const UINT16 DEFAULT_DST_PORT = 1234;
#define DEFAULT_DST_MAC_ADDR "12-34-56-78-9A-BC"

extern INT g_IfIndex;
extern BOOLEAN output_stdout;
extern CHAR* modestr;

typedef enum {
    ModeRx,
    ModeTx,
    ModeFwd,
    ModeLat,
} MODE;

extern MODE mode;

typedef enum {
    XdpModeSystem,
    XdpModeGeneric,
    XdpModeNative,
} XDP_MODE;

void
PrintRing(
    CHAR* Name,
    XSK_RING_INFO RingInfo
);
void
PrintRingInfo(
    XSK_RING_INFO_SET InfoSet
);

class NicAdapter;
extern NicAdapter* g_LocalAdapter;

UINT32
RingPairReserve(
    _In_ XSK_RING* ConsumerRing,
    _Out_ UINT32* ConsumerIndex,
    _In_ XSK_RING* ProducerRing,
    _Out_ UINT32* ProducerIndex,
    _In_ UINT32 MaxCount
);
class RssQueue {
private:
    std::string memPath;
public:
    INT queueId;
    HANDLE sock;
    HANDLE rxProgram;
    XDP_MODE xdpMode;
    UINT64 umemSize;
    ULONG umemchunkSize;
    ULONG umemHeadroom;
    ULONG txiosize;
    ULONG iobatchsize;
    UINT32 ringSize;
    UCHAR* txPattern;
    UINT32 txPatternLength;
    UCHAR* txPayload;
    INT64* latSamples;
    UINT32 latSamplesCount;
    UINT32 latIndex;
    XSK_POLL_MODE pollMode;
    uint64_t reqPPS{ 0 };

    ULONG payloadsize;

    struct {
        BOOLEAN periodicStats : 1;
        BOOLEAN rx : 1;
        BOOLEAN tx : 1;
        BOOLEAN optimizePoking : 1;
        BOOLEAN rxInject : 1;
        BOOLEAN txInspect : 1;
    } flags;

    double statsArray[STATS_ARRAY_SIZE];
    ULONG currStatsArrayIdx;

    ULONGLONG lastTick;
    ULONGLONG packetCount;
    ULONGLONG lastPacketCount;
    ULONGLONG lastRxDropCount;
    ULONGLONG pokesRequestedCount;
    ULONGLONG lastPokesRequestedCount;
    ULONGLONG pokesPerformedCount;
    ULONGLONG lastPokesPerformedCount;

    XSK_RING rxRing;
    XSK_RING txRing;
    XSK_RING fillRing;
    XSK_RING compRing;
    XSK_RING freeRxRing;
    XSK_RING freeTxRing;
    XSK_UMEM_REG umemReg;
public:
    RssQueue() {
        memset(this, 0, sizeof(*this));
        this->umemSize = DEFAULT_UMEM_SIZE;
        this->umemchunkSize = DEFAULT_UMEM_CHUNK_SIZE;
        this->umemHeadroom = DEFAULT_UMEM_HEADROOM;
        this->iobatchsize = DEFAULT_IO_BATCH;

        this->pollMode = XSK_POLL_MODE_DEFAULT;
        this->flags.optimizePoking = TRUE;

        this->queueId = -1;
        this->xdpMode = XdpModeSystem;
        //this->umemsize = DEFAULT_UMEM_SIZE;
        //this->umemchunksize = DEFAULT_UMEM_CHUNK_SIZE;
        //this->umemheadroom = DEFAULT_UMEM_HEADROOM;
        //this->iobatchsize = DEFAULT_IO_BATCH;
        //this->pollMode = XSK_POLL_MODE_DEFAULT;
        //this->flags.optimizePoking = TRUE;
        this->txiosize = DEFAULT_TX_IO_SIZE;
        this->latSamplesCount = DEFAULT_LAT_COUNT;

        this->payloadsize = DEFAULT_PAYLOAD_SIZE;
        this->txPayload = NULL;
    }
private:
    void notifyDriver(XSK_NOTIFY_FLAGS DirectionFlags);
    void writeTxPackets(
        UINT32 FreeConsumerIndex,
        UINT32 TxProducerIndex,
        UINT32 Count);
	void readCompletionPackets(
		UINT32 CompConsumerIndex,
		UINT32 FreeProducerIndex,
		UINT32 Count);
	void readRxPackets(
		UINT32 RxConsumerIndex,
		UINT32 FreeProducerIndex,
		UINT32 Count);
	void writeFillPackets(
		UINT32 FreeConsumerIndex,
		UINT32 FillProducerIndex,
		UINT32 Count
	);
    BOOL initSharedMemory();
    BOOL initFreeRing();
    BOOL initDataPath(INT ifindex) ;
    BOOL attachXdpProgram(INT ifindex);
public:

    void SetMemory(UINT64 umemsize, ULONG umemchunksize) ;
    // Initialization for socket
	void SetupSock(INT IfIndex);

    // Functions for running modes.
	UINT32 ProcessTx(BOOLEAN Wait);
	UINT32 ProcessRx(BOOLEAN Wait);
    UINT32 ProcessFwd(BOOLEAN Wait);
    UINT32 ProcessLat(BOOLEAN Wait);

    // Helpers for stats
    void PrintFinalStats();
    void PrintFinalLatStats();
    void ProcessPeriodicStats() ;

	UINT32 IssueRequest();
};


