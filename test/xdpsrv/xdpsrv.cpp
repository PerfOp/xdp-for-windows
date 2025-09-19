//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

#include "rss_queue.h"
#include "internal_utils.h"
#include "xdpsrv.h"
#include "netport.h"
#include "work_load.h"

#pragma warning(disable:4200) // nonstandard extension used: zero-sized array in struct/union

ULONG benchDuration = DEFAULT_DURATION;
BOOLEAN processDone = FALSE;
CHAR* modestr;
HANDLE periodicStatsEvent;

CHAR* HELP =
"xdpsrv.exe <rx|tx|fwd|lat> -i <ifindex> [OPTIONS] <-t THREAD_PARAMS> [-t THREAD_PARAMS...] \n"
"or\n"
"xdpsrv.exe <rx|tx|fwd|lat> -srcip <localip> [OPTIONS] <-t THREAD_PARAMS> [-t THREAD_PARAMS...] \n"
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
"   -reqpps <reqpps>   The preassigned query pps, default value is 0, which means no other limits\n"
"                      Default: " STR_OF(DEFAULT_REQ_PPS) "\n"
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
"   -dst               Destination: host ip and port \n"
"   -dstmac            Destination: host mac, not necessary, should check with the switch. \n"
"   -tx_payload        Pattern for the payload to TX, in hexadecimal.\n"
//"   -tx_pattern        Pattern for the leading bytes of TX, in hexadecimal.\n"
//"                      The pktcmd.exe tool outputs hexadecimal headers. Any\n"
//"                      trailing bytes in the XSK buffer are set to zero\n"
//"                      Default: \"\"\n"
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
"   xdpsrv.exe rx -i 6 -t -q -id 0\n"
"   xdpsrv.exe rx -i 6 -t -ca 0x2 -q -id 0 -t -ca 0x4 -q -id 1\n"
"   xdpsrv.exe tx -i 6 -t -q -id 0 -q -id 1\n"
"   xdpsrv.exe fwd -i 6 -t -q -id 0 -y\n"
"   xdpsrv.exe lat -i 6 -t -q -id 0 -ring_size 8\n"
;

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
DoRxMode(
    NetThread * Thread
)
{
    for (UINT32 qIndex = 0; qIndex < Thread->queueCount; qIndex++) {
        RssQueue* queue = &Thread->queues[qIndex];

        queue->flags.rx = TRUE;
        //SetupSock(g_IfIndex, queue);
        //queue->SetupSock(g_IfIndex);
        queue->SetupSock(g_LocalAdapter->GetIfindex());
        queue->lastTick = GetTickCount64();
    }

    printf("Receiving...\n");
    SetEvent(Thread->readyEvent);

    while (!ReadBooleanNoFence(&processDone)) {
        BOOLEAN Processed = FALSE;

        for (UINT32 qIndex = 0; qIndex < Thread->queueCount; qIndex++) {
            //Processed |= !!ProcessRx(&Thread->queues[qIndex], Thread->wait);
            Processed |= !!Thread->queues[qIndex].ProcessRx(Thread->wait);
        }

        if (!Processed) {
            for (UINT32 i = 0; i < Thread->yieldCount; i++) {
                YieldProcessor();
            }
        }
    }
}

VOID
DoTxMode(
    NetThread * Thread
)
{
    for (UINT32 qIndex = 0; qIndex < Thread->queueCount; qIndex++) {
        RssQueue* queue = &Thread->queues[qIndex];

        queue->flags.tx = TRUE;
        //SetupSock(g_IfIndex, queue);
        //queue->SetupSock(g_IfIndex);
        queue->SetupSock(g_LocalAdapter->GetIfindex());
        queue->lastTick = GetTickCount64();
    }

    printf("Sending...\n");
    SetEvent(Thread->readyEvent);

    while (!ReadBooleanNoFence(&processDone)) {
        BOOLEAN Processed = FALSE;

        for (UINT32 qIndex = 0; qIndex < Thread->queueCount; qIndex++) {
            //Processed |= ProcessTx(&Thread->queues[qIndex], Thread->wait);
            Processed |= Thread->queues[qIndex].ProcessTx(Thread->wait);
        }

        if (!Processed) {
            for (UINT32 i = 0; i < Thread->yieldCount; i++) {
                YieldProcessor();
            }
        }

    }
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
        //SetupSock(g_IfIndex, queue);
        //queue->SetupSock(g_IfIndex);
        queue->SetupSock(g_LocalAdapter->GetIfindex());
        queue->lastTick = GetTickCount64();
    }

    printf("Forwarding...\n");
    SetEvent(Thread->readyEvent);

    while (!ReadBooleanNoFence(&processDone)) {
        BOOLEAN Processed = FALSE;

        for (UINT32 qIndex = 0; qIndex < Thread->queueCount; qIndex++) {
            //Processed |= !!ProcessFwd(&Thread->queues[qIndex], Thread->wait);
            Processed |= !!Thread->queues[qIndex].ProcessFwd(Thread->wait);
        }

        if (!Processed) {
            for (UINT32 i = 0; i < Thread->yieldCount; i++) {
                YieldProcessor();
            }
        }

    }
}

VOID
DoLatMode(
    NetThread * Thread
)
{
    for (UINT32 qIndex = 0; qIndex < Thread->queueCount; qIndex++) {
        RssQueue* queue = &Thread->queues[qIndex];

        queue->flags.rx = TRUE;
        queue->flags.tx = TRUE;
        //SetupSock(g_IfIndex, queue);
        //queue->SetupSock(g_IfIndex);
        queue->SetupSock(g_LocalAdapter->GetIfindex());

        queue->IssueRequest();
    }

    printf("Probing latency...\n");
    SetEvent(Thread->readyEvent);

    while (!ReadBooleanNoFence(&processDone)) {
        BOOLEAN Processed = FALSE;

        for (UINT32 qIndex = 0; qIndex < Thread->queueCount; qIndex++) {
            //Processed |= !!ProcessLat(&Thread->queues[qIndex], Thread->wait);
            Processed |= !!Thread->queues[qIndex].ProcessLat(Thread->wait);
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
            Queue->ringSize = atoi(argv[i]);
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
            if(Queue->txPayload!=NULL){
                printf_error("Payload was setting by previous -tx_payload, please check the parameter \n");
                ABORT("Payload was setting by previous -tx_payload, please check the parameter \n");
			}
            Queue->payloadsize = atoi(argv[i]);
            Queue->txPayload = (UCHAR*)malloc(Queue->payloadsize);
            ASSERT_FRE(Queue->txPayload != NULL);
            memset(Queue->txPayload, 0, Queue->payloadsize);
        }
        else if (!_stricmp(argv[i], "-reqpps")) {
            if (++i >= argc) {
                Usage();
            }
            Queue->reqPPS = atoi(argv[i]);
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
        else if (!strcmp(argv[i], "-dst")) {
            if (++i >= argc) {
                Usage();
            }
            char ip_out[64] = { 0 };
            int port_out = 0;
            if (parseAddress(argv[i], ip_out, port_out)) {
                dstipidx = i;
                g_LocalAdapter->SetTarget(ip_out, DEFAULT_DST_MAC_ADDR, (UINT16)port_out);
            }
            else {
                printf("Please input the valid dst machine!\n");
                Usage();
            }
        }
        else if (!strcmp(argv[i], "-dstmac")) {
            if (++i >= argc) {
                Usage();
            }
            if (dstipidx > 0) {
                char ip_out[64] = { 0 };
                int port_out = 0;
                if (parseAddress(argv[dstipidx], ip_out, port_out)) {
                    g_LocalAdapter->SetTarget(ip_out, argv[i], (UINT16)port_out);
                }
                else {
                    printf("Please input the valid dst machine!\n");
                    Usage();
                }
            }
            else {
                Usage();
            }
        }
        /*
           else if (!strcmp(argv[i], "-tx_pattern")) {
           if (++i >= argc) {
           Usage();
           }
           Queue->txPatternLength = (UINT32)strlen(argv[i]);
           ASSERT_FRE(Queue->txPatternLength > 0 && Queue->txPatternLength % 2 == 0);
           Queue->txPatternLength /= 2;
           Queue->txPattern = (UCHAR*)malloc(Queue->txPatternLength);
           ASSERT_FRE(Queue->txPattern != NULL);
           HexStringToByte(Queue->txPattern, Queue->txPatternLength, argv[i]);
           }
           */
        else if (!strcmp(argv[i], "-tx_payload")) {
            if (++i >= argc) {
                Usage();
            }
            if ((strlen(argv[i]) % 2) != 0) {
                printf_error("Invalid tx_payload argument: %s\n", argv[i]);
                ABORT("The tx_payload must be a hexadecimal string with an even number of characters.\n");
            }
            if(Queue->txPayload!=NULL){
                printf_error("Payload was setting by previous -payloadsize, please check the parameter \n");
                ABORT("Payload was setting by previous -payloadsize, please check the parameter \n");
			}
            Queue->payloadsize = (UINT32)strlen(argv[i]) >> 1;
            Queue->txPayload = (UCHAR*)malloc(Queue->payloadsize);
            ASSERT_FRE(Queue->txPayload != NULL);
            //ASSERT_FRE(hex_string_to_bytes(argv[i], Queue->txPayload, Queue->payloadsize)>0);
            HexStringToByte(Queue->txPayload, Queue->payloadsize, argv[i]);
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

    g_LocalAdapter->debug_output();

    if (Queue->queueId == -1) {
        Usage();
    }

    if (Queue->ringSize == 0) {
        Queue->SetMemoryParam(umemsize, umemchunksize);
    }


    if (workMode == ModeLat) {
        ASSERT_FRE(
            Queue->umemchunkSize - Queue->umemHeadroom >= Queue->txPatternLength + sizeof(UINT64));

        Queue->latSamples = (INT64*)malloc(Queue->latSamplesCount * sizeof(*Queue->latSamples));
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
        workMode = ModeRx;
    }
    else if (!_stricmp(argv[i], "tx")) {
        workMode = ModeTx;
    }
    else if (!_stricmp(argv[i], "fwd")) {
        workMode = ModeFwd;
    }
    else if (!_stricmp(argv[i], "lat")) {
        workMode = ModeLat;
    }
    else {
        Usage();
    }
    modestr = argv[i];
    ++i;

    if (!strcmp(argv[i], "-i")) {
        if (++i >= argc) {
            Usage();
        }
        if (!g_LocalAdapter->InitLocalByIdx(atoi(argv[i++]), 4321)) {
            printf_error("Failed to initialize local adapter by ifindex %d\n", g_LocalAdapter->GetIfindex());
            ABORT("Check if the interface is up and XDP is enabled on it.\n");
            //Usage();
        }
    }
    else if (!strcmp(argv[i], "-srcip")) {
        if (++i >= argc) {
            Usage();
        }
        if (!g_LocalAdapter->InitLocalByIP(argv[i++], 4321)) {
            printf_error("Failed to initialize local adapter by srcip %s\n", argv[i]);
            ABORT("Check if the interface is up and XDP is enabled on it.\n");
        }
    }

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
            benchDuration = atoi(argv[i]);
        }
        else if (!strcmp(argv[i], "-v")) {
            logVerbose = TRUE;
        }
        else if (!strcmp(argv[i], "-o")) {
            outputStdout = TRUE;
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

    if (g_LocalAdapter->GetIfindex() == -1) {
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
XdpPollingThread(
    LPVOID lpThreadParameter
)
{
    NetThread* thread = (NetThread*)lpThreadParameter;
    HRESULT res;

    // Affinitize ASAP: memory allocations implicitly target the current
    // NUMA node, including kernel XDP allocations.
    res = SetThreadAffinities(thread);
    ASSERT_FRE(res == S_OK);

    if (workMode == ModeRx) {
        DoRxMode(thread);
    }
    else if (workMode == ModeTx) {
        DoTxMode(thread);
    }
    else if (workMode == ModeFwd) {
        DoFwdMode(thread);
    }
    else if (workMode == ModeLat) {
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
    benchDuration = 0;
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
    g_LocalAdapter = new NicAdapter();

    ParseArgs(&threads, &threadCount, argc, argv);

    periodicStatsEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    ASSERT_FRE(periodicStatsEvent != NULL);

    ASSERT_FRE(SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE));

    for (UINT32 tIndex = 0; tIndex < threadCount; tIndex++) {
        threads[tIndex].readyEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
        ASSERT_FRE(threads[tIndex].readyEvent != NULL);
        threads[tIndex].threadHandle =
            CreateThread(NULL, 0, XdpPollingThread, &threads[tIndex], 0, NULL);
        ASSERT_FRE(threads[tIndex].threadHandle != NULL);
        WaitForSingleObject(threads[tIndex].readyEvent, INFINITE);
    }

    while (benchDuration-- > 0) {
        WaitForSingleObject(periodicStatsEvent, 1000);
        for (UINT32 tIndex = 0; tIndex < threadCount; tIndex++) {
            NetThread* Thread = &threads[tIndex];
            for (UINT32 qIndex = 0; qIndex < Thread->queueCount; qIndex++) {
                //ProcessPeriodicStats(&Thread->queues[qIndex]);
                Thread->queues[qIndex].ProcessPeriodicStats();
            }
        }
    }

    WriteBooleanNoFence(&processDone, TRUE);

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
