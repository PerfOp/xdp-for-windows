#include "rss_queue.h"
#include "netport.h"
#include "internal_utils.h"

MODE mode;

INT g_IfIndex = -1;
XSK_POLL_MODE g_PollMode;
AdapterMeta* g_LocalAdapter=NULL;

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
PrintRing(
    CHAR* Name,
    XSK_RING_INFO RingInfo
)
{
    if (RingInfo.Size != 0) {
        printf_verbose(
            "%s\tring:\n\tva=0x%p\n\tsize=%d\n\tdescriptorsOff=%d\n\t"
            "producerIndexOff=%d(%lu)\n\tconsumerIndexOff=%d(%lu)\n\t"
            "flagsOff=%d(%lu)\n\telementStride=%d\n",
            Name, RingInfo.Ring, RingInfo.Size, RingInfo.DescriptorsOffset,
            RingInfo.ProducerIndexOffset,
            *(UINT32*)(RingInfo.Ring + RingInfo.ProducerIndexOffset),
            RingInfo.ConsumerIndexOffset,
            *(UINT32*)(RingInfo.Ring + RingInfo.ConsumerIndexOffset),
            RingInfo.FlagsOffset,
            *(UINT32*)(RingInfo.Ring + RingInfo.FlagsOffset),
            RingInfo.ElementStride);
    }
}

VOID
PrintRingInfo(
    XSK_RING_INFO_SET InfoSet
)
{
    PrintRing("rx", InfoSet.Rx);
    PrintRing("tx", InfoSet.Tx);
    PrintRing("fill", InfoSet.Fill);
    PrintRing("comp", InfoSet.Completion);
}



void RssQueue::SetMemory(UINT64 umemsize, ULONG umemchunksize) {
	UINT64 RingSize64 = umemsize / umemchunksize;
	ASSERT_FRE(RingSize64 <= MAXUINT32);
	this->umemSize = umemsize;
	this->umemchunkSize = umemchunksize;
	this->ringsize = (UINT32)RingSize64;

	ASSERT_FRE(this->umemSize >= this->umemchunkSize);
	ASSERT_FRE(this->umemchunkSize >= this->umemHeadroom);
	ASSERT_FRE(this->umemchunkSize - this->umemHeadroom >= this->txPatternLength);
};

BOOL RssQueue::InitSharedMemory() {
    this->umemReg.ChunkSize = this->umemchunkSize;
    this->umemReg.Headroom = this->umemHeadroom;
    this->umemReg.TotalSize = 2 * this->umemSize;

    if (largePages) {
        //
        // The memory subsystem requires allocations and mappings be aligned to
        // the large page size. XDP ignores the final chunk, if truncated.
        //
        this->umemReg.TotalSize = ALIGN_UP_BY(this->umemReg.TotalSize, GetLargePageMinimum());
    }
    this->umemReg.Address =
        VirtualAlloc(
            NULL, this->umemReg.TotalSize,
            (largePages ? MEM_LARGE_PAGES : 0) | MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_FRE(this->umemReg.Address != NULL);

	return TRUE;
};
 
BOOL RssQueue::InitDataPath(INT ifindex) {
	HRESULT res;
	UINT32 bindFlags = 0;
	res =
		XskSetSockopt(
			this->sock, XSK_SOCKOPT_UMEM_REG, &this->umemReg,
			sizeof(this->umemReg));
	ASSERT_FRE(res == S_OK);

	printf_verbose("configuring fill ring with size %d\n", this->ringsize);
	res =
		XskSetSockopt(
			this->sock, XSK_SOCKOPT_RX_FILL_RING_SIZE, &this->ringsize,
            sizeof(this->ringsize));
    ASSERT_FRE(res == S_OK);

    printf_verbose("configuring completion ring with size %d\n", this->ringsize);
    res =
        XskSetSockopt(
            this->sock, XSK_SOCKOPT_TX_COMPLETION_RING_SIZE, &this->ringsize,
            sizeof(this->ringsize));
    ASSERT_FRE(res == S_OK);

    if (this->flags.rx) {
        printf_verbose("configuring rx ring with size %d\n", this->ringsize);
        res =
            XskSetSockopt(
                this->sock, XSK_SOCKOPT_RX_RING_SIZE, &this->ringsize,
                sizeof(this->ringsize));
        ASSERT_FRE(res == S_OK);
        bindFlags |= XSK_BIND_FLAG_RX;
    }
    if (this->flags.tx) {
        printf_verbose("configuring tx ring with size %d\n", this->ringsize);
        res =
            XskSetSockopt(
                this->sock, XSK_SOCKOPT_TX_RING_SIZE, &this->ringsize,
                sizeof(this->ringsize));
        ASSERT_FRE(res == S_OK);
        bindFlags |= XSK_BIND_FLAG_TX;
    }

    if (this->xdpMode == XdpModeGeneric) {
        bindFlags |= XSK_BIND_FLAG_GENERIC;
    }
    else if (this->xdpMode == XdpModeNative) {
        bindFlags |= XSK_BIND_FLAG_NATIVE;
    }

    if (this->flags.rxInject) {
        //XDP_HOOK_ID hookId = { 0 };
        XDP_HOOK_ID hookId;
        memset(&hookId, 0, sizeof(XDP_HOOK_ID));
        hookId.Layer = XDP_HOOK_L2;
        hookId.Direction = XDP_HOOK_RX;
        hookId.SubLayer = XDP_HOOK_INJECT;

        printf_verbose("configuring tx inject to rx\n");
        res = XskSetSockopt(this->sock, XSK_SOCKOPT_TX_HOOK_ID, &hookId, sizeof(hookId));
        ASSERT_FRE(res == S_OK);
    }

    if (this->flags.txInspect) {
        //XDP_HOOK_ID hookId = { 0 };
        XDP_HOOK_ID hookId;
        memset(&hookId, 0, sizeof(XDP_HOOK_ID));
        hookId.Layer = XDP_HOOK_L2;
        hookId.Direction = XDP_HOOK_TX;
        hookId.SubLayer = XDP_HOOK_INSPECT;

        printf_verbose("configuring rx from tx inspect\n");
        res = XskSetSockopt(this->sock, XSK_SOCKOPT_RX_HOOK_ID, &hookId, sizeof(hookId));
        ASSERT_FRE(res == S_OK);
    }

	printf_verbose(
		"binding sock to ifindex %d queueId %d flags 0x%x\n", ifindex, this->queueId, bindFlags);
	res = XskBind(this->sock, ifindex, this->queueId, (XSK_BIND_FLAGS)bindFlags);
	ASSERT_FRE(res == S_OK);

	printf_verbose("activating sock\n");
	res = XskActivate(this->sock, (XSK_ACTIVATE_FLAGS)0);
	ASSERT_FRE(res == S_OK);

	printf_verbose("XSK_SOCKOPT_RING_INFO\n");
	XSK_RING_INFO_SET infoSet = { 0 };
	UINT32 ringInfoSize = sizeof(infoSet);
	res = XskGetSockopt(this->sock, XSK_SOCKOPT_RING_INFO, &infoSet, &ringInfoSize);
	ASSERT_FRE(res == S_OK);
	ASSERT_FRE(ringInfoSize == sizeof(infoSet));
	PrintRingInfo(infoSet);

	XskRingInitialize(&this->fillRing, &infoSet.Fill);
	XskRingInitialize(&this->compRing, &infoSet.Completion);

	if (this->flags.rx) {
		XskRingInitialize(&this->rxRing, &infoSet.Rx);
	}
	if (this->flags.tx) {
		XskRingInitialize(&this->txRing, &infoSet.Tx);
	}

	res =
		XskSetSockopt(
			this->sock, XSK_SOCKOPT_POLL_MODE, &this->pollMode, sizeof(this->pollMode));
	ASSERT_FRE(res == S_OK);

	return TRUE;
};

BOOL RssQueue::AttachXdpProgram(INT ifindex) {
	//XDP_RULE rule = { 0 };
    XDP_RULE rule;
    memset(&rule, 0, sizeof(XDP_RULE));

    UINT32 curflags = 0;
    XDP_HOOK_ID hookId;
    UINT32 hookSize = sizeof(hookId);
    HRESULT res;

    if (!this->flags.rx) {
        return FALSE;
    }

    rule.Match = udpDestPort == 0 ? XDP_MATCH_ALL : XDP_MATCH_UDP_DST;
    rule.Pattern.Port = _byteswap_ushort(udpDestPort);
    rule.Action = XDP_PROGRAM_ACTION_REDIRECT;
    rule.Redirect.TargetType = XDP_REDIRECT_TARGET_TYPE_XSK;
    rule.Redirect.Target = this->sock;

    if (this->xdpMode == XdpModeGeneric) {
        curflags |= XDP_CREATE_PROGRAM_FLAG_GENERIC;
    }
    else if (this->xdpMode == XdpModeNative) {
        curflags |= XDP_CREATE_PROGRAM_FLAG_NATIVE;
    }

    res = XskGetSockopt(this->sock, XSK_SOCKOPT_RX_HOOK_ID, &hookId, &hookSize);
    ASSERT_FRE(SUCCEEDED(res));
    ASSERT_FRE(hookSize == sizeof(hookId));

    res =
        XdpCreateProgram(
            ifindex, &hookId, this->queueId, (XDP_CREATE_PROGRAM_FLAGS)curflags, &rule, 1, &this->rxProgram);
    if (FAILED(res)) {
        ABORT("XdpCreateProgram failed: %d\n", res);
    }

	return TRUE;
}

BOOL RssQueue::InitRing() {
    //
    // Free ring starts off with all UMEM descriptors.
    //
    UINT64 numDescriptors64 = this->umemSize / this->umemchunkSize;
    printf("Created %lld buffer on %lld bytes memory with chunksize %ld on the queue\n", 
        numDescriptors64, 
        this->umemSize, 
        this->umemchunkSize);
    ASSERT_FRE(numDescriptors64 <= MAXUINT32);
    UINT32 numDescriptors = (UINT32)numDescriptors64;
    typedef struct {
        UINT32 Producer;
        UINT32 Consumer;
        UINT32 Flags;
        UINT64 Descriptors[0];
    } SFreeRingLayout;

    SFreeRingLayout* FreeRingLayout =
        (SFreeRingLayout*)calloc(1, sizeof(*FreeRingLayout) + numDescriptors * sizeof(*FreeRingLayout->Descriptors));
    ASSERT_FRE(FreeRingLayout != NULL);

    //XSK_RING_INFO freeRxRingInfo = { 0 };
    XSK_RING_INFO freeRxRingInfo;
    memset(&freeRxRingInfo, 0, sizeof(freeRxRingInfo));

    freeRxRingInfo.Ring = (BYTE*)FreeRingLayout;
    freeRxRingInfo.ProducerIndexOffset = (UINT32)STRUCT_FIELD_OFFSET(FreeRingLayout, Producer);
    freeRxRingInfo.ConsumerIndexOffset = (UINT32)STRUCT_FIELD_OFFSET(FreeRingLayout, Consumer);
    freeRxRingInfo.FlagsOffset = (UINT32)STRUCT_FIELD_OFFSET(FreeRingLayout, Flags);
    freeRxRingInfo.DescriptorsOffset = (UINT32)STRUCT_FIELD_OFFSET(FreeRingLayout, Descriptors[0]);
    freeRxRingInfo.Size = numDescriptors;
    freeRxRingInfo.ElementStride = sizeof(*FreeRingLayout->Descriptors);
    XskRingInitialize(&this->freeRxRing, &freeRxRingInfo);
    PrintRing("free", freeRxRingInfo);

    //const UINT32 kPacketSize = 64;
    UCHAR* payload = new UCHAR[this->payloadsize];
    memset(payload, 0, this->payloadsize);
    UINT32 genPacketSize;
    BYTE MtuBuffer[2048];
    memset(MtuBuffer, 0, sizeof(MtuBuffer));
    /*
    char refBuffer[] = "123456789abc7c1e523ef5d808004500005c000000000111a2b00a0201720a02016c10e104d20048d2c900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\0";
    UINT32 refSize = (UINT32)strlen(refBuffer);
    BYTE* decodedMtu = new BYTE[refSize / 2];
    memset((VOID*)decodedMtu, 0, refSize/2);
    // Assert::AreEqual(kPacketSize, refSize / 2);
    GetDescriptorPattern(decodedMtu, refSize, refBuffer);

    */
    /*
    AdapterMeta localAdapter;
    localAdapter.SetTarget("10.2.1.108", "12-34-56-78-9a-bc", 1234);
    localAdapter.AssingLocal("10.2.1.114", "7C-1E-52-3E-F5-D8", 4321);
    */
    g_LocalAdapter->FillMTUBufferWithPayload(payload, this->payloadsize, genPacketSize, MtuBuffer);
    /*
    for (UINT32 i = 0; i < genPacketSize; i++) {
        if (MtuBuffer[i] != decodedMtu[i]) {
            printf("Mismatch at index %d: expected %02x, got %02x\n", i, decodedMtu[i], MtuBuffer[i]);
        }
    }
    */
    
    //Queue->localAdapter.FillMTUBufferWithPayload(payload, Queue->txPatternLength, packetSize, MtuBuffer);
    
    //delete[] decodedMtu;
    delete[] payload;
    
    UINT64 desc = 0;
    for (UINT32 i = 0; i < numDescriptors; i++) {
        UINT64* Descriptor = (UINT64*)XskRingGetElement(&this->freeRxRing, i);
        *Descriptor = desc;

        if (mode == ModeTx || mode == ModeLat) {
            memcpy(
                (UCHAR*)this->umemReg.Address + desc + this->umemHeadroom, 
                //Queue->txPattern,
                MtuBuffer,
                //Queue->txPatternLength);
                genPacketSize);
        }

        desc += this->umemchunkSize;
    }

    XskRingProducerSubmit(&this->freeRxRing, numDescriptors);
    return TRUE;
}
 
INT
LatCmp(
    const VOID * A,
    const VOID * B
)
{
    const UINT64* a = (const UINT64*)A;
    const UINT64* b = (const UINT64*)B;
    return (*a > *b) - (*a < *b);
}

VOID
RssQueue::ProcessPeriodicStats(
    //RssQueue * Queue
)
{
    UINT64 currentTick = GetTickCount64();
    UINT64 tickDiff = currentTick - this->lastTick;
    UINT64 packetcount;
    UINT64 packetDiff;
    double kpps;

    if (tickDiff == 0) {
        return;
    }

    packetcount = this->packetCount;
    packetDiff = packetcount - this->lastPacketCount;
    kpps = (packetDiff) ? (double)packetDiff / tickDiff : 0;

    if (this->flags.periodicStats) {
        XSK_STATISTICS stats;
        UINT32 optSize = sizeof(stats);
        ULONGLONG pokesRequested = this->pokesRequestedCount;
        ULONGLONG pokesPerformed = this->pokesPerformedCount;
        ULONGLONG pokesRequestedDiff;
        ULONGLONG pokesPerformedDiff;
        ULONGLONG pokesAvoidedPercentage;
        ULONGLONG rxDropDiff;
        double rxDropKpps;

        if (pokesPerformed > pokesRequested) {
            //
            // Since these statistics aren't protected by synchronization, it's
            // possible instruction reordering resulted in (pokesPerformed >
            // pokesRequested). We know pokesPerformed <= pokesRequested, so
            // correct this.
            //
            pokesRequested = pokesPerformed;
        }

        pokesRequestedDiff = pokesRequested - this->lastPokesRequestedCount;
        pokesPerformedDiff = pokesPerformed - this->lastPokesPerformedCount;

        if (pokesRequestedDiff == 0) {
            pokesAvoidedPercentage = 0;
        }
        else {
            pokesAvoidedPercentage =
                (pokesRequestedDiff - pokesPerformedDiff) * 100 / pokesRequestedDiff;
        }

        HRESULT res =
            XskGetSockopt(this->sock, XSK_SOCKOPT_STATISTICS, &stats, &optSize);
        ASSERT_FRE(res == S_OK);
        ASSERT_FRE(optSize == sizeof(stats));

        rxDropDiff = stats.RxDropped - this->lastRxDropCount;
        rxDropKpps = rxDropDiff ? (double)rxDropDiff / tickDiff : 0;
        this->lastRxDropCount = stats.RxDropped;

        printf("%s[%d]: %9.3f kpps %9.3f rxDropKpps rxDrop:%llu rxTrunc:%llu "
            "rxBadDesc:%llu txBadDesc:%llu pokesAvoided:%llu%%\n",
            modestr, this->queueId, kpps, rxDropKpps, stats.RxDropped, stats.RxTruncated,
            stats.RxInvalidDescriptors, stats.TxInvalidDescriptors,
            pokesAvoidedPercentage);

        this->lastPokesRequestedCount = pokesRequested;
        this->lastPokesPerformedCount = pokesPerformed;
    }

    this->statsArray[this->currStatsArrayIdx++ % STATS_ARRAY_SIZE] = kpps;
    this->lastPacketCount = packetcount;
    this->lastTick = currentTick;
}

VOID
RssQueue::PrintFinalLatStats()
{
    LARGE_INTEGER FreqQpc;
    VERIFY(QueryPerformanceFrequency(&FreqQpc));

    qsort(this->latSamples, this->latIndex, sizeof(*this->latSamples), LatCmp);

    for (UINT32 i = 0; i < this->latIndex; i++) {
        this->latSamples[i] = QpcToUs64(this->latSamples[i], FreqQpc.QuadPart);
    }

    printf(
        "%-3s[%d]: min=%llu P50=%llu P90=%llu P99=%llu P99.9=%llu P99.99=%llu P99.999=%llu P99.9999=%llu us rtt\n",
        modestr, this->queueId,
        this->latSamples[0],
        this->latSamples[(UINT32)(this->latIndex * 0.5)],
        this->latSamples[(UINT32)(this->latIndex * 0.9)],
        this->latSamples[(UINT32)(this->latIndex * 0.99)],
        this->latSamples[(UINT32)(this->latIndex * 0.999)],
        this->latSamples[(UINT32)(this->latIndex * 0.9999)],
        this->latSamples[(UINT32)(this->latIndex * 0.99999)],
        this->latSamples[(UINT32)(this->latIndex * 0.999999)]);
}

VOID
RssQueue::PrintFinalStats()
{
    ULONG numEntries = min(this->currStatsArrayIdx, STATS_ARRAY_SIZE);
    ULONG numEntriesIgnored = 0;
    double min = 99999999;
    double max = 0;
    double sum = 0;
    double avg = 0;
    double stdDev = 0;

    if (numEntries < 4) {
        //
        // We ignore first and last data points and standard deviation
        // calculation needs at least 2 data points.
        //
        printf_error(
            "%-3s[%d] Not enough data points collected for a statistical analysis\n",
            modestr, this->queueId);
        return;
    }

    //
    // Scrub the statistics by ignoring the first and last entries.
    //
    if (this->currStatsArrayIdx <= STATS_ARRAY_SIZE) {
        this->statsArray[0] = 0;
        numEntriesIgnored++;
    }
    this->statsArray[(this->currStatsArrayIdx - 1) % STATS_ARRAY_SIZE] = 0;
    numEntriesIgnored++;

    //
    // Average, min and max.
    //
    for (ULONG i = 0; i < numEntries; i++) {
        if (this->statsArray[i] == 0) {
            continue;
        }

        sum += this->statsArray[i];
        min = min(min, this->statsArray[i]);
        max = max(max, this->statsArray[i]);
    }

    numEntries -= numEntriesIgnored;
    avg = sum / numEntries;

    //
    // Standard deviation.
    //
    for (ULONG i = 0; i < numEntries; i++) {
        if (this->statsArray[i] == 0) {
            continue;
        }

        stdDev += pow(this->statsArray[i] - avg, 2);
    }

    stdDev = sqrt(stdDev / (numEntries - 1));

    printf("%-3s[%d]: avg=%08.3f stddev=%08.3f min=%08.3f max=%08.3f Kpps\n",
        modestr, this->queueId, avg, stdDev, min, max);

    if (mode == ModeLat) {
        //PrintFinalLatStats(this);
        PrintFinalLatStats();
    }
}


