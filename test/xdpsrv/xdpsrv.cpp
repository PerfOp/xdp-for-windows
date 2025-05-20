//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

#include "rss_queue.h"
#include "internal_utils.h"
#include "xdpsrv.h"
#include "netport.h"

#pragma warning(disable:4200) // nonstandard extension used: zero-sized array in struct/union
    
//AdapterMeta g_LocalAdapter;

//UINT16 udpDestPort = DEFAULT_UDP_DEST_PORT;
ULONG duration = DEFAULT_DURATION;
//BOOLEAN verbose = FALSE;
BOOLEAN output_stdout = FALSE;
BOOLEAN done = FALSE;
//BOOLEAN largePages = FALSE;
//MODE mode;
CHAR* modestr;
HANDLE periodicStatsEvent;

CHAR* HELP =
"xskbench.exe <rx|tx|fwd|lat> -i <ifindex> [OPTIONS] <-t THREAD_PARAMS> [-t THREAD_PARAMS...] \n"
"\n"
"THREAD_PARAMS: \n"
"   -q <QUEUE_PARAMS> [-q QUEUE_PARAMS...] \n"
"   -w                 Wait for IO completion\n"
"                      Default: off (busy loop IO mode)\n"
"   -na <nodenumber>   The NUMA node affinity. -1 is any node\n"
"                      Default: " STR_OF(DEFAULT_NODE_AFFINITY) "\n"
"   -group <groupid>   The processor group. -1 is any group\n"
"                      Must be specified alongside -ca\n"
"                      Default: " STR_OF(DEFAULT_GROUP) "\n"
"   -ci <cpuindex>     The ideal CPU. -1 is any CPU\n"
"                      Default: " STR_OF(DEFAULT_IDEAL_CPU) "\n"
"   -ca <cpumask>      The CPU affinity mask. 0 is any CPU\n"
"                      Must be specified alongside -group\n"
"                      Default: " STR_OF(DEFAULT_CPU_AFFINITY) "\n"
"   -yield <count>     The number of yield instructions to execute after the\n"
"                      thread performs no work.\n"
"                      Default: " STR_OF(DEFAULT_YIELD_COUNT) "\n"
"\n"
"QUEUE_PARAMS: \n"
"   -id <queueid>      Required. The queue ID.\n"
"   -ring_size <size>  The ring size (in number of descriptors) of all AF_XDP rings\n"
"                      Default: <umemsize> / <umemchunksize>\n"
"   -u <umemsize>      The total size (in bytes) of the UMEM\n"
"                      Default: " STR_OF(DEFAULT_UMEM_SIZE) "\n"
"   -c <umemchunksize> The size (in bytes) of UMEM chunks\n"
"                      Default: " STR_OF(DEFAULT_UMEM_CHUNK_SIZE) "\n"
"   -h <headroom>      The size (in bytes) of UMEM chunk headroom\n"
"                      Default: " STR_OF(DEFAULT_UMEM_HEADROOM) "\n"
"   -txio <txiosize>   The size (in bytes) of each IO in tx mode\n"
"                      Default: " STR_OF(DEFAULT_TX_IO_SIZE) "\n"
"   -payloadsize <payloadsize>   The size (in bytes) of payload.\n"
"                      Default: " STR_OF(DEFAULT_PAYLOAD_SIZE) "\n"
"   -b <iobatchsize>   The number of buffers to submit for IO at once\n"
"                      Default: " STR_OF(DEFAULT_IO_BATCH) "\n"
"   -ignore_needpoke   Ignore the NEED_POKE optimization mechanism\n"
"                      Default: off (Use NEED_POKE)\n"
"   -poll <mode>       The preferred socket polling mode:\n"
"                      - system:  The system default polling mode\n"
"                      - busy:    The system aggressively polls\n"
"                      - socket:  The socket polls\n"
"                      Default: system\n"
"   -xdp_mode <mode>   The XDP interface provider:\n"
"                      - system:  The system determines the ideal XDP provider\n"
"                      - generic: A generic XDP interface provider\n"
"                      - native:  A native XDP interface provider\n"
"                      Default: system\n"
"   -s                 Periodic socket statistics output\n"
"                      Default: off\n"
"   -rx_inject         Inject TX and FWD frames onto the local RX path\n"
"                      Default: off\n"
"   -tx_inspect        Inspect RX and FWD frames from the local TX path\n"
"                      Default: off\n"
"   -srcip             Source: host ip \n"
"   -dstip             Destination: host ip \n"
"   -dstmac            Destination: host mac, Please use -dstip to assign destination IP before -dstmac \n"
"   -tx_pattern        Pattern for the leading bytes of TX, in hexadecimal.\n"
"                      The pktcmd.exe tool outputs hexadecimal headers. Any\n"
"                      trailing bytes in the XSK buffer are set to zero\n"
"                      Default: \"\"\n"
"   -lat_count         Number of latency samples to collect\n"
"                      Default: " STR_OF(DEFAULT_LAT_COUNT) "\n"

"\n"
"OPTIONS: \n"
"   -d                 Duration of execution in seconds\n"
"                      Default: infinite\n"
"   -v                 Verbose logging\n"
"                      Default: off\n"
"   -o                 Stdout logging\n"
"                      Default: off\n"
"   -p <udpPort>       The UDP destination port, or 0 for all traffic.\n"
"                      Default: " STR_OF(DEFAULT_UDP_DEST_PORT) "\n"
"   -lp                Use large pages. Requires privileged account.\n"
"                      Default: off\n"
"\n"
"Examples\n"
"   xskbench.exe rx -i 6 -t -q -id 0\n"
"   xskbench.exe rx -i 6 -t -ca 0x2 -q -id 0 -t -ca 0x4 -q -id 1\n"
"   xskbench.exe tx -i 6 -t -q -id 0 -q -id 1\n"
"   xskbench.exe fwd -i 6 -t -q -id 0 -y\n"
"   xskbench.exe lat -i 6 -t -q -id 0 -ring_size 8\n"
;

/*
UINT32
RingPairReserve(
    _In_ XSK_RING* ConsumerRing,
    _Out_ UINT32* ConsumerIndex,
    _In_ XSK_RING* ProducerRing,
    _Out_ UINT32* ProducerIndex,
    _In_ UINT32 MaxCount
)
{
    MaxCount = XskRingConsumerReserve(ConsumerRing, MaxCount, ConsumerIndex);
    MaxCount = XskRingProducerReserve(ProducerRing, MaxCount, ProducerIndex);
    return MaxCount;
}
VOID
AttachXdpProgram(
    RssQueue* Queue
)
{
    //XDP_RULE rule = { 0 };
    XDP_RULE rule;
    memset(&rule, 0, sizeof(XDP_RULE));

    UINT32 flags = 0;
    XDP_HOOK_ID hookId;
    UINT32 hookSize = sizeof(hookId);
    HRESULT res;

    if (!Queue->flags.rx) {
        return;
    }

    rule.Match = udpDestPort == 0 ? XDP_MATCH_ALL : XDP_MATCH_UDP_DST;
    rule.Pattern.Port = _byteswap_ushort(udpDestPort);
    rule.Action = XDP_PROGRAM_ACTION_REDIRECT;
    rule.Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSK;
    rule.Redirect.Target = Queue->sock;

    if (Queue->xdpMode == XdpModeGeneric) {
        flags |= XDP_CREATE_PROGRAM_FLAG_GENERIC;
    }
    else if (Queue->xdpMode == XdpModeNative) {
        flags |= XDP_CREATE_PROGRAM_FLAG_NATIVE;
    }

    res = XskGetSockopt(Queue->sock, XSK_SOCKOPT_RX_HOOK_ID, &hookId, &hookSize);
    ASSERT_FRE(SUCCEEDED(res));
    ASSERT_FRE(hookSize == sizeof(hookId));

    res =
        XdpCreateProgram(
            g_IfIndex, &hookId, Queue->queueId, (XDP_CREATE_PROGRAM_FLAGS)flags, &rule, 1, &Queue->rxProgram);
    if (FAILED(res)) {
        ABORT("XdpCreateProgram failed: %d\n", res);
    }
}
*/
VOID
EnableLargePages(
    VOID
)
{
    HANDLE Token = NULL;
    TOKEN_PRIVILEGES TokenPrivileges;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &Token)) {
        goto Failure;
    }

    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValue(NULL, SE_LOCK_MEMORY_NAME, &TokenPrivileges.Privileges[0].Luid)) {
        goto Failure;
    }
    if (!AdjustTokenPrivileges(Token, FALSE, &TokenPrivileges, 0, NULL, 0)) {
        goto Failure;
    }
    if (GetLastError() != ERROR_SUCCESS) {
        goto Failure;
    }

    CloseHandle(Token);

    return;

Failure:

    ABORT("Failed to acquire large page privileges. See \"Assigning Privileges to an Account\"\n");
}


_Success_(return)
BOOLEAN
ParseUInt64A(
    _In_z_ const CHAR * Arg,
    _Out_ UINT64 * Result
)
{
    // detect hex
    const CHAR* Fmt = (Arg[0] == '0' && Arg[1] == 'x') ? "%llx%n" : "%llu%n";
    INT End = 0;

    if (1 != sscanf_s(Arg, Fmt, Result, &End) || Arg[End] != L'\0') {
        printf_verbose("Invalid integer value: %s\n", Arg);
        return FALSE;
    }

    return TRUE;
}

_Success_(return)
BOOLEAN
ParseUInt32A(
    _In_z_ const CHAR * Arg,
    _Out_ UINT32 * Result
)
{
    UINT64 Tmp;

    if (!ParseUInt64A(Arg, &Tmp)) {
        return FALSE;
    }

    if (Tmp > MAXUINT32) {
        printf_verbose("Invalid integer value: %s\n", Arg);
        return FALSE;
    }

    *Result = (UINT32)Tmp;
    return TRUE;
}

VOID
SetupSock(
    INT IfIndex,
    RssQueue * Queue
)
{
    HRESULT res;
    //UINT32 bindFlags = 0;

    printf_verbose("creating sock\n");
    res = XskCreate(&Queue->sock);
    if (res != S_OK) {
        ABORT("err: XskCreate returned %d\n", res);
    }

    printf_verbose("XDP_UMEM_REG\n");

    Queue->InitSharedMemory();
	Queue->InitDataPath(IfIndex);

    Queue->InitRing();
    
    Queue->AttachXdpProgram(IfIndex);
}

VOID
NotifyDriver(
    RssQueue * Queue,
    XSK_NOTIFY_FLAGS DirectionFlags
)
{
    HRESULT res;
    XSK_NOTIFY_RESULT_FLAGS notifyResult;

    if (Queue->flags.optimizePoking) {
        //
        // Ensure poke flags are read after writing producer/consumer indices.
        //
        XdpBarrierBetweenReleaseAndAcquire();

        if ((DirectionFlags & XSK_NOTIFY_FLAG_POKE_RX) && !XskRingProducerNeedPoke(&Queue->fillRing)) {
            DirectionFlags &= ~XSK_NOTIFY_FLAG_POKE_RX;
        }
        if ((DirectionFlags & XSK_NOTIFY_FLAG_POKE_TX) && !XskRingProducerNeedPoke(&Queue->txRing)) {
            DirectionFlags &= ~XSK_NOTIFY_FLAG_POKE_TX;
        }
    }

    Queue->pokesRequestedCount++;

    if (DirectionFlags != 0) {
        Queue->pokesPerformedCount++;
        res =
            XskNotifySocket(
                Queue->sock, DirectionFlags, WAIT_DRIVER_TIMEOUT_MS, &notifyResult);

        if (DirectionFlags & (XSK_NOTIFY_FLAG_WAIT_RX | XSK_NOTIFY_FLAG_WAIT_TX)) {
            ASSERT_FRE(res == S_OK || res == HRESULT_FROM_WIN32(ERROR_TIMEOUT));
        }
        else {
            ASSERT_FRE(res == S_OK);
            ASSERT_FRE(notifyResult == 0);
        }
    }
}

VOID
WriteFillPackets(
    RssQueue * Queue,
    UINT32 FreeConsumerIndex,
    UINT32 FillProducerIndex,
    UINT32 Count
)
{
    for (UINT32 i = 0; i < Count; i++) {
        UINT64* freeDesc = (UINT64*)XskRingGetElement(&Queue->freeRxRing, FreeConsumerIndex++);
        UINT64* fillDesc = (UINT64*)XskRingGetElement(&Queue->fillRing, FillProducerIndex++);

        *fillDesc = *freeDesc;
        printf_verbose("Producing FILL entry {address:%llu}}\n", *freeDesc);
    }
}

VOID
ReadRxPackets(
    RssQueue * Queue,
    UINT32 RxConsumerIndex,
    UINT32 FreeProducerIndex,
    UINT32 Count
)
{
    for (UINT32 i = 0; i < Count; i++) {
        XSK_BUFFER_DESCRIPTOR* rxDesc = (XSK_BUFFER_DESCRIPTOR*)XskRingGetElement(&Queue->rxRing, RxConsumerIndex++);
        UINT64* freeDesc = (UINT64*)XskRingGetElement(&Queue->freeRxRing, FreeProducerIndex++);

        *freeDesc = rxDesc->Address.BaseAddress;
        printf_verbose("Consuming RX entry   {address:%llu, offset:%llu, length:%d}\n",
            rxDesc->Address.BaseAddress, rxDesc->Address.Offset, rxDesc->Length);

        if (output_stdout) {
            void* pEthHdr =
                (void*)((UCHAR*)Queue->umemReg.Address + rxDesc->Address.BaseAddress + rxDesc->Address.Offset);
            PrintPacketMeta(pEthHdr);
        }
    }
}

UINT32
ProcessRx(
    RssQueue * Queue,
    BOOLEAN Wait
)
{
    XSK_NOTIFY_FLAGS notifyFlags = XSK_NOTIFY_FLAG_NONE;
    UINT32 available;
    UINT32 consumerIndex;
    UINT32 producerIndex;
    UINT32 processed = 0;

    available =
        RingPairReserve(
            &Queue->rxRing, &consumerIndex, &Queue->freeRxRing, &producerIndex, Queue->iobatchsize);
    if (available > 0) {
        ReadRxPackets(Queue, consumerIndex, producerIndex, available);
        XskRingConsumerRelease(&Queue->rxRing, available);
        XskRingProducerSubmit(&Queue->freeRxRing, available);

        processed += available;
        Queue->packetCount += available;
    }

    available =
        RingPairReserve(
            &Queue->freeRxRing, &consumerIndex, &Queue->fillRing, &producerIndex, Queue->iobatchsize);
    if (available > 0) {
        WriteFillPackets(Queue, consumerIndex, producerIndex, available);
        XskRingConsumerRelease(&Queue->freeRxRing, available);
        XskRingProducerSubmit(&Queue->fillRing, available);

        processed += available;
        notifyFlags |= XSK_NOTIFY_FLAG_POKE_RX;
    }

    if (Wait &&
        XskRingConsumerReserve(&Queue->rxRing, 1, &consumerIndex) == 0 &&
        XskRingConsumerReserve(&Queue->freeRxRing, 1, &consumerIndex) == 0) {
        notifyFlags |= XSK_NOTIFY_FLAG_WAIT_RX;
    }

    if (Queue->pollMode == XSK_POLL_MODE_SOCKET) {
        //
        // If socket poll mode is supported by the program, always enable pokes.
        //
        notifyFlags |= XSK_NOTIFY_FLAG_POKE_RX;
    }

    if (notifyFlags != 0) {
        NotifyDriver(Queue, notifyFlags);
    }

    return processed;
}

VOID
DoRxMode(
    NetThread * Thread
)
{
    for (UINT32 qIndex = 0; qIndex < Thread->queueCount; qIndex++) {
        RssQueue* queue = &Thread->queues[qIndex];

        queue->flags.rx = TRUE;
        SetupSock(g_IfIndex, queue);
        queue->lastTick = GetTickCount64();
    }

    printf("Receiving...\n");
    SetEvent(Thread->readyEvent);

    while (!ReadBooleanNoFence(&done)) {
        BOOLEAN Processed = FALSE;

        for (UINT32 qIndex = 0; qIndex < Thread->queueCount; qIndex++) {
            Processed |= !!ProcessRx(&Thread->queues[qIndex], Thread->wait);
        }

        if (!Processed) {
            for (UINT32 i = 0; i < Thread->yieldCount; i++) {
                YieldProcessor();
            }
        }
    }
}

VOID
WriteTxPackets(
    RssQueue * Queue,
    UINT32 FreeConsumerIndex,
    UINT32 TxProducerIndex,
    UINT32 Count
)
{
    for (UINT32 i = 0; i < Count; i++) {
        UINT64* freeDesc = (UINT64*)XskRingGetElement(&Queue->freeRxRing, FreeConsumerIndex++);
        XSK_BUFFER_DESCRIPTOR* txDesc = (XSK_BUFFER_DESCRIPTOR*)XskRingGetElement(&Queue->txRing, TxProducerIndex++);

        txDesc->Address.BaseAddress = *freeDesc;
        assert(Queue->umemReg.Headroom <= MAXUINT16);
        txDesc->Address.Offset = (UINT16)Queue->umemReg.Headroom;
        txDesc->Length = Queue->txiosize;
        //
        // This benchmark does not write data into the TX packet.
        //
        printf_verbose("Producing TX entry {address:%llu, offset:%llu, length:%d}\n",
            txDesc->Address.BaseAddress, txDesc->Address.Offset, txDesc->Length);
    }
}

VOID
ReadCompletionPackets(
    RssQueue * Queue,
    UINT32 CompConsumerIndex,
    UINT32 FreeProducerIndex,
    UINT32 Count
)
{
    for (UINT32 i = 0; i < Count; i++) {
        UINT64* compDesc = (UINT64*)XskRingGetElement(&Queue->compRing, CompConsumerIndex++);
        UINT64* freeDesc = (UINT64*)XskRingGetElement(&Queue->freeRxRing, FreeProducerIndex++);

        *freeDesc = *compDesc;
        printf_verbose("Consuming COMP entry {address:%llu}\n", *compDesc);
    }
}

UINT32
ProcessTx(
    RssQueue * Queue,
    BOOLEAN Wait
)
{
    XSK_NOTIFY_FLAGS notifyFlags = XSK_NOTIFY_FLAG_NONE;
    UINT32 available;
    UINT32 consumerIndex;
    UINT32 producerIndex;
    UINT32 processed = 0;

    available =
        RingPairReserve(
            &Queue->compRing, &consumerIndex, &Queue->freeRxRing, &producerIndex, Queue->iobatchsize);
    if (available > 0) {
        ReadCompletionPackets(Queue, consumerIndex, producerIndex, available);
        XskRingConsumerRelease(&Queue->compRing, available);
        XskRingProducerSubmit(&Queue->freeRxRing, available);

        processed += available;
        Queue->packetCount += available;

        if (XskRingProducerReserve(&Queue->txRing, MAXUINT32, &producerIndex) !=
            Queue->txRing.Size) {
            notifyFlags |= XSK_NOTIFY_FLAG_POKE_TX;
        }
    }

    available =
        RingPairReserve(
            &Queue->freeRxRing, &consumerIndex, &Queue->txRing, &producerIndex, Queue->iobatchsize);
    if (available > 0) {
        WriteTxPackets(Queue, consumerIndex, producerIndex, available);
        XskRingConsumerRelease(&Queue->freeRxRing, available);
        XskRingProducerSubmit(&Queue->txRing, available);

        processed += available;
        notifyFlags |= XSK_NOTIFY_FLAG_POKE_TX;
    }

    if (Wait &&
        XskRingConsumerReserve(&Queue->compRing, 1, &consumerIndex) == 0 &&
        XskRingConsumerReserve(&Queue->freeRxRing, 1, &consumerIndex) == 0) {
        notifyFlags |= XSK_NOTIFY_FLAG_WAIT_TX;
    }

    if (Queue->pollMode == XSK_POLL_MODE_SOCKET) {
        //
        // If socket poll mode is supported by the program, always enable pokes.
        //
        notifyFlags |= XSK_NOTIFY_FLAG_POKE_TX;
    }

    if (notifyFlags != 0) {
        NotifyDriver(Queue, notifyFlags);
    }

    return processed;
}

VOID
DoTxMode(
    NetThread * Thread
)
{
    for (UINT32 qIndex = 0; qIndex < Thread->queueCount; qIndex++) {
        RssQueue* queue = &Thread->queues[qIndex];

        queue->flags.tx = TRUE;
        SetupSock(g_IfIndex, queue);
        queue->lastTick = GetTickCount64();
    }

    printf("Sending...\n");
    SetEvent(Thread->readyEvent);

    while (!ReadBooleanNoFence(&done)) {
        BOOLEAN Processed = FALSE;

        for (UINT32 qIndex = 0; qIndex < Thread->queueCount; qIndex++) {
            Processed |= ProcessTx(&Thread->queues[qIndex], Thread->wait);
        }

        if (!Processed) {
            for (UINT32 i = 0; i < Thread->yieldCount; i++) {
                YieldProcessor();
            }
        }

    }
}

UINT32
ProcessFwd(
    RssQueue * Queue,
    BOOLEAN Wait
)
{
    XSK_NOTIFY_FLAGS notifyFlags = XSK_NOTIFY_FLAG_NONE;
    UINT32 available;
    UINT32 consumerIndex;
    UINT32 producerIndex;
    UINT32 processed = 0;

    //
    // Move packets from the RX ring to the TX ring.
    //
    available =
        RingPairReserve(
            &Queue->rxRing, &consumerIndex, &Queue->txRing, &producerIndex, Queue->iobatchsize);
    if (available > 0) {
        for (UINT32 i = 0; i < available; i++) {
            XSK_BUFFER_DESCRIPTOR* rxDesc = (XSK_BUFFER_DESCRIPTOR*)XskRingGetElement(&Queue->rxRing, consumerIndex++);
            XSK_BUFFER_DESCRIPTOR* txDesc = (XSK_BUFFER_DESCRIPTOR*)XskRingGetElement(&Queue->txRing, producerIndex++);

            printf_verbose("Consuming RX entry   {address:%llu, offset:%llu, length:%d}\n",
                rxDesc->Address.BaseAddress, rxDesc->Address.Offset, rxDesc->Length);

            txDesc->Address = rxDesc->Address;
            txDesc->Length = rxDesc->Length;

            if (Queue->flags.rxInject == Queue->flags.txInspect) {
                //
                // Swap MAC addresses.
                //
                CHAR* ethHdr =
                    (CHAR*)Queue->umemReg.Address + txDesc->Address.BaseAddress +
                    txDesc->Address.Offset;
                CHAR tmp[6];
                memcpy(tmp, ethHdr, sizeof(tmp));
                memcpy(ethHdr, ethHdr + 6, sizeof(tmp));
                memcpy(ethHdr + 6, tmp, sizeof(tmp));
            }

            printf_verbose("Producing TX entry {address:%llu, offset:%llu, length:%d}\n",
                txDesc->Address.BaseAddress, txDesc->Address.Offset, txDesc->Length);
        }

        XskRingConsumerRelease(&Queue->rxRing, available);
        XskRingProducerSubmit(&Queue->txRing, available);

        processed += available;
        notifyFlags |= XSK_NOTIFY_FLAG_POKE_TX;
    }

    //
    // Move packets from the completion ring to the free ring.
    //
    available =
        RingPairReserve(
            &Queue->compRing, &consumerIndex, &Queue->freeRxRing, &producerIndex, Queue->iobatchsize);
    if (available > 0) {
        for (UINT32 i = 0; i < available; i++) {
            UINT64* compDesc = (UINT64*)XskRingGetElement(&Queue->compRing, consumerIndex++);
            UINT64* freeDesc = (UINT64*)XskRingGetElement(&Queue->freeRxRing, producerIndex++);

            *freeDesc = *compDesc;

            printf_verbose("Consuming COMP entry {address:%llu}\n", *compDesc);
        }

        XskRingConsumerRelease(&Queue->compRing, available);
        XskRingProducerSubmit(&Queue->freeRxRing, available);

        processed += available;
        Queue->packetCount += available;

        if (XskRingProducerReserve(&Queue->txRing, MAXUINT32, &producerIndex) !=
            Queue->txRing.Size) {
            notifyFlags |= XSK_NOTIFY_FLAG_POKE_TX;
        }
    }

    //
    // Move packets from the free ring to the fill ring.
    //
    available =
        RingPairReserve(
            &Queue->freeRxRing, &consumerIndex, &Queue->fillRing, &producerIndex, Queue->iobatchsize);
    if (available > 0) {
        for (UINT32 i = 0; i < available; i++) {
            UINT64* freeDesc = (UINT64*)XskRingGetElement(&Queue->freeRxRing, consumerIndex++);
            UINT64* fillDesc = (UINT64*)XskRingGetElement(&Queue->fillRing, producerIndex++);

            *fillDesc = *freeDesc;

            printf_verbose("Producing FILL entry {address:%llu}\n", *freeDesc);
        }

        XskRingConsumerRelease(&Queue->freeRxRing, available);
        XskRingProducerSubmit(&Queue->fillRing, available);

        processed += available;
        notifyFlags |= XSK_NOTIFY_FLAG_POKE_RX;
    }

    if (Wait &&
        XskRingConsumerReserve(&Queue->rxRing, 1, &consumerIndex) == 0 &&
        XskRingConsumerReserve(&Queue->compRing, 1, &consumerIndex) == 0 &&
        XskRingConsumerReserve(&Queue->freeRxRing, 1, &consumerIndex) == 0) {
        notifyFlags |= (XSK_NOTIFY_FLAG_WAIT_RX | XSK_NOTIFY_FLAG_WAIT_TX);
    }

    if (Queue->pollMode == XSK_POLL_MODE_SOCKET) {
        //
        // If socket poll mode is supported by the program, always enable pokes.
        //
        notifyFlags |= (XSK_NOTIFY_FLAG_POKE_RX | XSK_NOTIFY_FLAG_POKE_TX);
    }

    if (notifyFlags != 0) {
        NotifyDriver(Queue, notifyFlags);
    }

    return processed;
}

VOID
DoFwdMode(
    NetThread * Thread
)
{
    for (UINT32 qIndex = 0; qIndex < Thread->queueCount; qIndex++) {
        RssQueue* queue = &Thread->queues[qIndex];

        queue->flags.rx = TRUE;
        queue->flags.tx = TRUE;
        SetupSock(g_IfIndex, queue);
        queue->lastTick = GetTickCount64();
    }

    printf("Forwarding...\n");
    SetEvent(Thread->readyEvent);

    while (!ReadBooleanNoFence(&done)) {
        BOOLEAN Processed = FALSE;

        for (UINT32 qIndex = 0; qIndex < Thread->queueCount; qIndex++) {
            Processed |= !!ProcessFwd(&Thread->queues[qIndex], Thread->wait);
        }

        if (!Processed) {
            for (UINT32 i = 0; i < Thread->yieldCount; i++) {
                YieldProcessor();
            }
        }

    }
}

UINT32
ProcessLat(
    RssQueue * Queue,
    BOOLEAN Wait
)
{
    XSK_NOTIFY_FLAGS notifyFlags = XSK_NOTIFY_FLAG_NONE;
    UINT32 available;
    UINT32 consumerIndex;
    UINT32 producerIndex;
    UINT32 processed = 0;

    //
    // Move frames from the RX ring to the RX fill ring, recording the timestamp
    // deltas as we go.
    //
    available =
        RingPairReserve(
            &Queue->rxRing, &consumerIndex, &Queue->fillRing, &producerIndex, Queue->iobatchsize);
    if (available > 0) {
        LARGE_INTEGER NowQpc;
        VERIFY(QueryPerformanceCounter(&NowQpc));

        for (UINT32 i = 0; i < available; i++) {
            XSK_BUFFER_DESCRIPTOR* rxDesc = (XSK_BUFFER_DESCRIPTOR*)XskRingGetElement(&Queue->rxRing, consumerIndex++);
            UINT64* fillDesc = (UINT64*)XskRingGetElement(&Queue->fillRing, producerIndex++);

            printf_verbose(
                "Consuming RX entry   {address:%llu, offset:%llu, length:%d}\n",
                rxDesc->Address.BaseAddress, rxDesc->Address.Offset,
                rxDesc->Length);

            INT64 UNALIGNED* Timestamp = (INT64 UNALIGNED*)
                ((CHAR*)Queue->umemReg.Address + rxDesc->Address.BaseAddress +
                    rxDesc->Address.Offset + Queue->txPatternLength);

            printf_verbose("latency: %lld\n", NowQpc.QuadPart - *Timestamp);

            if (Queue->latIndex < Queue->latSamplesCount) {
                Queue->latSamples[Queue->latIndex++] = NowQpc.QuadPart - *Timestamp;
            }

            *fillDesc = rxDesc->Address.BaseAddress;

            printf_verbose("Producing FILL entry {address:%llu}\n", *fillDesc);
        }

        XskRingConsumerRelease(&Queue->rxRing, available);
        XskRingProducerSubmit(&Queue->fillRing, available);

        processed += available;
        Queue->packetCount += available;

        notifyFlags |= XSK_NOTIFY_FLAG_POKE_RX;
    }

    //
    // Move frames from the TX completion ring to the free ring.
    //
    available =
        RingPairReserve(
            &Queue->compRing, &consumerIndex, &Queue->freeRxRing, &producerIndex, Queue->iobatchsize);
    if (available > 0) {
        ReadCompletionPackets(Queue, consumerIndex, producerIndex, available);
        XskRingConsumerRelease(&Queue->compRing, available);
        XskRingProducerSubmit(&Queue->freeRxRing, available);
        processed += available;

        if (XskRingProducerReserve(&Queue->txRing, MAXUINT32, &producerIndex) !=
            Queue->txRing.Size) {
            notifyFlags |= XSK_NOTIFY_FLAG_POKE_TX;
        }
    }

    //
    // Move frames from the free ring to the TX ring, stamping the current time
    // onto each frame.
    //
    available =
        RingPairReserve(
            &Queue->freeRxRing, &consumerIndex, &Queue->txRing, &producerIndex, Queue->iobatchsize);
    if (available > 0) {
        LARGE_INTEGER NowQpc;
        VERIFY(QueryPerformanceCounter(&NowQpc));

        for (UINT32 i = 0; i < available; i++) {
            UINT64* freeDesc = (UINT64*)XskRingGetElement(&Queue->freeRxRing, consumerIndex++);
            XSK_BUFFER_DESCRIPTOR* txDesc = (XSK_BUFFER_DESCRIPTOR*)XskRingGetElement(&Queue->txRing, producerIndex++);

            INT64 UNALIGNED* Timestamp = (INT64 UNALIGNED*)
                ((CHAR*)Queue->umemReg.Address + *freeDesc +
                    Queue->umemReg.Headroom + Queue->txPatternLength);
            *Timestamp = NowQpc.QuadPart;

            txDesc->Address.BaseAddress = *freeDesc;
            assert(Queue->umemReg.Headroom <= MAXUINT16);
            txDesc->Address.Offset = Queue->umemReg.Headroom;
            txDesc->Length = Queue->txiosize;

            printf_verbose(
                "Producing TX entry {address:%llu, offset:%llu, length:%d}\n",
                txDesc->Address.BaseAddress, txDesc->Address.Offset, txDesc->Length);
        }

        XskRingConsumerRelease(&Queue->freeRxRing, available);
        XskRingProducerSubmit(&Queue->txRing, available);

        processed += available;
        notifyFlags |= XSK_NOTIFY_FLAG_POKE_TX;
    }

    if (Wait &&
        XskRingConsumerReserve(&Queue->rxRing, 1, &consumerIndex) == 0 &&
        XskRingConsumerReserve(&Queue->compRing, 1, &consumerIndex) == 0 &&
        XskRingConsumerReserve(&Queue->freeRxRing, 1, &consumerIndex) == 0) {
        notifyFlags |= (XSK_NOTIFY_FLAG_WAIT_RX | XSK_NOTIFY_FLAG_WAIT_TX);
    }

    if (Queue->pollMode == XSK_POLL_MODE_SOCKET) {
        //
        // If socket poll mode is supported by the program, always enable pokes.
        //
        notifyFlags |= (XSK_NOTIFY_FLAG_POKE_RX | XSK_NOTIFY_FLAG_POKE_TX);
    }

    if (notifyFlags != 0) {
        NotifyDriver(Queue, notifyFlags);
    }

    return processed;
}

VOID
DoLatMode(
    NetThread * Thread
)
{
    for (UINT32 qIndex = 0; qIndex < Thread->queueCount; qIndex++) {
        RssQueue* queue = &Thread->queues[qIndex];
        UINT32 consumerIndex;
        UINT32 producerIndex;
        UINT32 available;

        queue->flags.rx = TRUE;
        queue->flags.tx = TRUE;
        SetupSock(g_IfIndex, queue);
        queue->lastTick = GetTickCount64();

        //
        // Fill up the RX fill ring. Once this initial fill is performed, the
        // RX fill ring and RX ring operate in a closed loop.
        //
        available = XskRingProducerReserve(&queue->fillRing, queue->ringsize, &producerIndex);
        ASSERT_FRE(available == queue->ringsize);
        available = XskRingConsumerReserve(&queue->freeRxRing, queue->ringsize, &consumerIndex);
        ASSERT_FRE(available == queue->ringsize);
        WriteFillPackets(queue, consumerIndex, producerIndex, available);
        XskRingConsumerRelease(&queue->freeRxRing, available);
        XskRingProducerSubmit(&queue->fillRing, available);
    }

    printf("Probing latency...\n");
    SetEvent(Thread->readyEvent);

    while (!ReadBooleanNoFence(&done)) {
        BOOLEAN Processed = FALSE;

        for (UINT32 qIndex = 0; qIndex < Thread->queueCount; qIndex++) {
            Processed |= !!ProcessLat(&Thread->queues[qIndex], Thread->wait);
        }

        if (!Processed) {
            for (UINT32 i = 0; i < Thread->yieldCount; i++) {
                YieldProcessor();
            }
        }
    }
}

VOID
PrintUsage(
    INT Line
)
{
    printf_error("Line:%d\n", Line);
    ABORT(HELP);
}

VOID
ParseQueueArgs(
    RssQueue * Queue,
    INT argc,
    CHAR * *argv
)
{
    UINT64 umemsize = DEFAULT_UMEM_SIZE;
    ULONG umemchunksize = DEFAULT_UMEM_CHUNK_SIZE;
    ULONG umemheadroom = DEFAULT_UMEM_HEADROOM;
    /*
    Queue->queueId = -1;
    Queue->xdpMode = XdpModeSystem;
    Queue->umemsize = DEFAULT_UMEM_SIZE;
    Queue->umemchunksize = DEFAULT_UMEM_CHUNK_SIZE;
    Queue->umemheadroom = DEFAULT_UMEM_HEADROOM;
    Queue->iobatchsize = DEFAULT_IO_BATCH;
    Queue->pollMode = XSK_POLL_MODE_DEFAULT;
    Queue->flags.optimizePoking = TRUE;
    Queue->txiosize = DEFAULT_TX_IO_SIZE;
    Queue->latSamplesCount = DEFAULT_LAT_COUNT;

    Queue->payloadsize = DEFAULT_PAYLOAD_SIZE;
    */
    INT dstipidx = -1;

    for (INT i = 0; i < argc; i++) {
        if (!_stricmp(argv[i], "-id")) {
            if (++i >= argc) {
                Usage();
            }
            Queue->queueId = atoi(argv[i]);
        }
        else if (!strcmp(argv[i], "-ring_size")) {
            if (++i >= argc) {
                Usage();
            }
            Queue->ringsize = atoi(argv[i]);
        }
        else if (!strcmp(argv[i], "-c")) {
            if (++i >= argc) {
                Usage();
            }
            //Queue->umemchunksize = atoi(argv[i]);
            umemchunksize = atoi(argv[i]);
        }
        else if (!_stricmp(argv[i], "-txio")) {
            if (++i >= argc) {
                Usage();
            }
            Queue->txiosize = atoi(argv[i]);
        }
        else if (!_stricmp(argv[i], "-payloadsize")) {
            if (++i >= argc) {
                Usage();
            }
            Queue->payloadsize = atoi(argv[i]);
        }
        else if (!strcmp(argv[i], "-u")) {
            if (++i >= argc) {
                Usage();
            }
            //if (!ParseUInt64A(argv[i], &Queue->umemsize)) {
            if (!ParseUInt64A(argv[i], &umemsize)) {
                Usage();
            }
        }
        else if (!strcmp(argv[i], "-b")) {
            if (++i >= argc) {
                Usage();
            }
            Queue->iobatchsize = atoi(argv[i]);
        }
        else if (!strcmp(argv[i], "-h")) {
            if (++i >= argc) {
                Usage();
            }
            //Queue->umemheadroom = atoi(argv[i]);
			umemheadroom = atoi(argv[i]);
        }
        else if (!strcmp(argv[i], "-s")) {
            Queue->flags.periodicStats = TRUE;
        }
        else if (!_stricmp(argv[i], "-ignore_needpoke")) {
            Queue->flags.optimizePoking = FALSE;
        }
        else if (!_stricmp(argv[i], "-poll")) {
            if (++i >= argc) {
                Usage();
            }
            if (!_stricmp(argv[i], "system")) {
                Queue->pollMode = XSK_POLL_MODE_DEFAULT;
            }
            else if (!_stricmp(argv[i], "busy")) {
                Queue->pollMode = XSK_POLL_MODE_BUSY;
            }
            else if (!_stricmp(argv[i], "socket")) {
                Queue->pollMode = XSK_POLL_MODE_SOCKET;
            }
            else {
                Usage();
            }
        }
        else if (!_stricmp(argv[i], "-xdp_mode")) {
            if (++i >= argc) {
                Usage();
            }
            if (!_stricmp(argv[i], "system")) {
                Queue->xdpMode = XdpModeSystem;
            }
            else if (!_stricmp(argv[i], "generic")) {
                Queue->xdpMode = XdpModeGeneric;
            }
            else if (!_stricmp(argv[i], "native")) {
                Queue->xdpMode = XdpModeNative;
            }
            else {
                Usage();
            }
        }
        else if (!strcmp(argv[i], "-rx_inject")) {
            Queue->flags.rxInject = TRUE;
        }
        else if (!strcmp(argv[i], "-tx_inspect")) {
            Queue->flags.txInspect = TRUE;
        }
        else if (!strcmp(argv[i], "-srcip")) {
            if (++i >= argc) {
                Usage();
            }
            g_LocalAdapter->InitLocalByIP(argv[i]);
        }
        else if (!strcmp(argv[i], "-dstip")) {
            if (++i >= argc) {
                Usage();
            }
            dstipidx = i;
            g_LocalAdapter->SetTarget(argv[i]);
        }
        else if (!strcmp(argv[i], "-dstmac")) {
            if (++i >= argc) {
                Usage();
            }
            if (dstipidx > 0) {
                g_LocalAdapter->SetTarget(argv[dstipidx], argv[i], 1234);
            }
            else {
                Usage();
            }
        }
        else if (!strcmp(argv[i], "-tx_pattern")) {
            if (++i >= argc) {
                Usage();
            }
            Queue->txPatternLength = (UINT32)strlen(argv[i]);
            ASSERT_FRE(Queue->txPatternLength > 0 && Queue->txPatternLength % 2 == 0);
            Queue->txPatternLength /= 2;
            Queue->txPattern = (UCHAR*)malloc(Queue->txPatternLength);
            ASSERT_FRE(Queue->txPattern != NULL);
            GetDescriptorPattern(Queue->txPattern, Queue->txPatternLength, argv[i]);
        }
        else if (!strcmp(argv[i], "-lat_count")) {
            if (++i >= argc) {
                Usage();
            }
            Queue->latSamplesCount = atoi(argv[i]);
        }
        else {
            Usage();
        }
    }

    if (Queue->queueId == -1) {
        Usage();
    }

    if (Queue->ringsize == 0) {
		Queue->SetMemory(umemsize, umemchunksize);
    }


    if (mode == ModeLat) {
        ASSERT_FRE(
            Queue->umemchunkSize - Queue->umemHeadroom >= Queue->txPatternLength + sizeof(UINT64));

        Queue->latSamples = (INT64 *)malloc(Queue->latSamplesCount * sizeof(*Queue->latSamples));
        ASSERT_FRE(Queue->latSamples != NULL);
        ZeroMemory(Queue->latSamples, Queue->latSamplesCount * sizeof(*Queue->latSamples));
    }
}

VOID
ParseThreadArgs(
    NetThread * Thread,
    INT argc,
    CHAR * *argv
)
{
    BOOLEAN groupSet = FALSE;
    BOOLEAN cpuAffinitySet = FALSE;

    Thread->wait = FALSE;
    Thread->nodeAffinity = DEFAULT_NODE_AFFINITY;
    Thread->idealCpu = DEFAULT_IDEAL_CPU;
    Thread->cpuAffinity = DEFAULT_CPU_AFFINITY;
    Thread->group = DEFAULT_GROUP;
    Thread->yieldCount = DEFAULT_YIELD_COUNT;

    for (INT i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "-q")) {
            Thread->queueCount++;
        }
        else if (!_stricmp(argv[i], "-na")) {
            if (++i >= argc) {
                Usage();
            }
            Thread->nodeAffinity = atoi(argv[i]);
        }
        else if (!_stricmp(argv[i], "-group")) {
            if (++i >= argc) {
                Usage();
            }
            Thread->group = atoi(argv[i]);
            groupSet = TRUE;
        }
        else if (!_stricmp(argv[i], "-ci")) {
            if (++i >= argc) {
                Usage();
            }
            Thread->idealCpu = atoi(argv[i]);
        }
        else if (!_stricmp(argv[i], "-ca")) {
            if (++i >= argc) {
                Usage();
            }
            Thread->cpuAffinity = (DWORD_PTR)_strtoui64(argv[i], NULL, 0);
            cpuAffinitySet = TRUE;
        }
        else if (!strcmp(argv[i], "-w")) {
            Thread->wait = TRUE;
        }
        else if (!_stricmp(argv[i], "-yield")) {
            if (++i >= argc) {
                Usage();
            }
            Thread->yieldCount = atoi(argv[i]);
        }
        else if (Thread->queueCount == 0) {
            Usage();
        }
    }

    if (Thread->queueCount == 0) {
        Usage();
    }

    if (Thread->wait && Thread->queueCount > 1) {
        printf_error("Waiting with multiple sockets per thread is not supported\n");
        Usage();
    }

    if (groupSet != cpuAffinitySet) {
        Usage();
    }

    //Thread->queues = (RssQueue*)calloc(Thread->queueCount, sizeof(*Thread->queues));
    Thread->queues = (RssQueue*)new RssQueue[Thread->queueCount];// , sizeof(*Thread->queues));
    ASSERT_FRE(Thread->queues != NULL);

    INT qStart = -1;
    INT qIndex = 0;
    for (INT i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "-q")) {
            if (qStart != -1) {
                ParseQueueArgs(&Thread->queues[qIndex++], i - qStart, &argv[qStart]);
            }
            qStart = i + 1;
        }
    }
    ParseQueueArgs(&Thread->queues[qIndex++], argc - qStart, &argv[qStart]);
}

VOID
ParseArgs(
    NetThread * *ThreadsPtr,
    UINT32 * ThreadCountPtr,
    INT argc,
    CHAR * *argv
)
{
    INT i = 1;
    UINT32 threadCount = 0;
    NetThread* threads = NULL;

    if (argc < 4) {
        Usage();
    }

    if (!_stricmp(argv[i], "rx")) {
        mode = ModeRx;
    }
    else if (!_stricmp(argv[i], "tx")) {
        mode = ModeTx;
    }
    else if (!_stricmp(argv[i], "fwd")) {
        mode = ModeFwd;
    }
    else if (!_stricmp(argv[i], "lat")) {
        mode = ModeLat;
    }
    else {
        Usage();
    }
    modestr = argv[i];
    ++i;

    if (strcmp(argv[i++], "-i")) {
        Usage();
    }
    g_IfIndex = atoi(argv[i++]);

    while (i < argc) {
        if (!strcmp(argv[i], "-t")) {
            threadCount++;
        }
        else if (!strcmp(argv[i], "-p")) {
            if (++i >= argc) {
                Usage();
            }
            udpDestPort = (UINT16)atoi(argv[i]);
        }
        else if (!strcmp(argv[i], "-d")) {
            if (++i >= argc) {
                Usage();
            }
            duration = atoi(argv[i]);
        }
        else if (!strcmp(argv[i], "-v")) {
            verbose = TRUE;
        }
        else if (!strcmp(argv[i], "-o")) {
            output_stdout = TRUE;
        }
        else if (!_stricmp(argv[i], "-lp")) {
            largePages = TRUE;
            EnableLargePages();
        }
        else if (threadCount == 0) {
            Usage();
        }

        ++i;
    }

    if (g_IfIndex == -1) {
        Usage();
    }

    if (threadCount == 0) {
        Usage();
    }

    threads = (NetThread*)calloc(threadCount, sizeof(*threads));
    ASSERT_FRE(threads != NULL);

    INT tStart = -1;
    INT tIndex = 0;
    for (i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "-t")) {
            if (tStart != -1) {
                ParseThreadArgs(&threads[tIndex++], i - tStart, &argv[tStart]);
            }
            tStart = i + 1;
        }
    }
    ParseThreadArgs(&threads[tIndex++], argc - tStart, &argv[tStart]);

    *ThreadsPtr = threads;
    *ThreadCountPtr = threadCount;
}

HRESULT
SetThreadAffinities(
    NetThread * Thread
)
{
    if (Thread->nodeAffinity != DEFAULT_NODE_AFFINITY) {
        GROUP_AFFINITY group;

        printf_verbose("setting node affinity %d\n", Thread->nodeAffinity);
        if (!GetNumaNodeProcessorMaskEx((USHORT)Thread->nodeAffinity, &group)) {
            assert(FALSE);
            return HRESULT_FROM_WIN32(GetLastError());
        }
        if (!SetThreadGroupAffinity(GetCurrentThread(), &group, NULL)) {
            assert(FALSE);
            return HRESULT_FROM_WIN32(GetLastError());
        }
    }

    if (Thread->group != DEFAULT_GROUP) {
        GROUP_AFFINITY group = { 0 };

        printf_verbose("setting CPU affinity mask 0x%llu\n", Thread->cpuAffinity);
        printf_verbose("setting group affinity %d\n", Thread->group);
        group.Mask = Thread->cpuAffinity;
        group.Group = (WORD)Thread->group;
        if (!SetThreadGroupAffinity(GetCurrentThread(), &group, NULL)) {
            assert(FALSE);
            return HRESULT_FROM_WIN32(GetLastError());
        }
    }

    if (Thread->idealCpu != DEFAULT_IDEAL_CPU) {
        DWORD oldCpu;
        printf_verbose("setting ideal CPU %d\n", Thread->idealCpu);
        oldCpu = SetThreadIdealProcessor(GetCurrentThread(), Thread->idealCpu);
        assert(oldCpu != -1);
        if (oldCpu == -1) {
            return HRESULT_FROM_WIN32(GetLastError());
        }
    }

    return S_OK;
}

DWORD
WINAPI
DoThread(
    LPVOID lpThreadParameter
)
{
    NetThread* thread = (NetThread*)lpThreadParameter;
    HRESULT res;

    // Affinitize ASAP: memory allocations implicitly target the current
    // NUMA node, including kernel XDP allocations.
    res = SetThreadAffinities(thread);
    ASSERT_FRE(res == S_OK);

    if (mode == ModeRx) {
        DoRxMode(thread);
    }
    else if (mode == ModeTx) {
        DoTxMode(thread);
    }
    else if (mode == ModeFwd) {
        DoFwdMode(thread);
    }
    else if (mode == ModeLat) {
        DoLatMode(thread);
    }

    return 0;
}

BOOL
WINAPI
ConsoleCtrlHandler(
    DWORD CtrlType
)
{
    UNREFERENCED_PARAMETER(CtrlType);

    // Force graceful exit.
    duration = 0;
    SetEvent(periodicStatsEvent);

    return TRUE;
}

INT
__cdecl
main(
    INT argc,
    CHAR * *argv
)
{
    NetThread* threads;
    UINT32 threadCount;
	g_LocalAdapter = new AdapterMeta();

    ParseArgs(&threads, &threadCount, argc, argv);

    periodicStatsEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    ASSERT_FRE(periodicStatsEvent != NULL);

    ASSERT_FRE(SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE));

    for (UINT32 tIndex = 0; tIndex < threadCount; tIndex++) {
        threads[tIndex].readyEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
        ASSERT_FRE(threads[tIndex].readyEvent != NULL);
        threads[tIndex].threadHandle =
            CreateThread(NULL, 0, DoThread, &threads[tIndex], 0, NULL);
        ASSERT_FRE(threads[tIndex].threadHandle != NULL);
        WaitForSingleObject(threads[tIndex].readyEvent, INFINITE);
    }

    while (duration-- > 0) {
        WaitForSingleObject(periodicStatsEvent, 1000);
        for (UINT32 tIndex = 0; tIndex < threadCount; tIndex++) {
            NetThread* Thread = &threads[tIndex];
            for (UINT32 qIndex = 0; qIndex < Thread->queueCount; qIndex++) {
                //ProcessPeriodicStats(&Thread->queues[qIndex]);
                Thread->queues[qIndex].ProcessPeriodicStats();
            }
        }
    }

    WriteBooleanNoFence(&done, TRUE);

    for (UINT32 tIndex = 0; tIndex < threadCount; tIndex++) {
        NetThread* Thread = &threads[tIndex];
        WaitForSingleObject(Thread->threadHandle, INFINITE);
        for (UINT32 qIndex = 0; qIndex < Thread->queueCount; qIndex++) {
            //PrintFinalStats(&Thread->queues[qIndex]);
            Thread->queues[qIndex].PrintFinalStats();
        }
    }
    delete g_LocalAdapter;

    return 0;
}
