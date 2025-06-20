#include "rss_queue.h"
#include "netport.h"
#include "internal_utils.h"
#include "highperf_timer.h"

MODE workMode;

XSK_POLL_MODE g_PollMode;
NicAdapter* g_LocalAdapter=NULL;

BOOLEAN outputStdout = FALSE;

void PrintRing(
    CHAR* Name,
    XSK_RING_INFO RingInfo
){
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

void PrintRingInfo(
    XSK_RING_INFO_SET InfoSet
){
    PrintRing("rx", InfoSet.Rx);
    PrintRing("tx", InfoSet.Tx);
    PrintRing("fill", InfoSet.Fill);
    PrintRing("comp", InfoSet.Completion);
}


UINT32 RingPairReserve(
    _In_ XSK_RING* ConsumerRing,
    _Out_ UINT32* ConsumerIndex,
    _In_ XSK_RING* ProducerRing,
    _Out_ UINT32* ProducerIndex,
    _In_ UINT32 MaxCount
){
    MaxCount = XskRingConsumerReserve(ConsumerRing, MaxCount, ConsumerIndex);
    MaxCount = XskRingProducerReserve(ProducerRing, MaxCount, ProducerIndex);
    return MaxCount;
}

void RssQueue::SetMemory(UINT64 umemsize, ULONG umemchunksize) {
	UINT64 RingSize64 = umemsize / umemchunksize;
	ASSERT_FRE(RingSize64 <= MAXUINT32);
	this->umemSize = umemsize;
	this->umemchunkSize = umemchunksize;
	this->ringSize = (UINT32)RingSize64;

	ASSERT_FRE(this->umemSize >= this->umemchunkSize);
	ASSERT_FRE(this->umemchunkSize >= this->umemHeadroom);
	ASSERT_FRE(this->umemchunkSize - this->umemHeadroom >= this->txPatternLength);
};

BOOL RssQueue::initSharedMemory() {
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
 
BOOL RssQueue::initDataPath(INT ifindex) {
	HRESULT res;
	UINT32 bindFlags = 0;

    // 1. Register umem memory
    res =
		XskSetSockopt(
			this->sock, XSK_SOCKOPT_UMEM_REG, &this->umemReg,
			sizeof(this->umemReg));
	ASSERT_FRE(res == S_OK);

    // 2. Register fillring's size on InBound path
	printf_verbose("configuring fill ring with size %d\n", this->ringSize);
	res =
		XskSetSockopt(
			this->sock, XSK_SOCKOPT_RX_FILL_RING_SIZE, &this->ringSize,
            sizeof(this->ringSize));
    ASSERT_FRE(res == S_OK);

    // 3. Register compring's size on OutBound path
    printf_verbose("configuring completion ring with size %d\n", this->ringSize);
    res =
        XskSetSockopt(
            this->sock, XSK_SOCKOPT_TX_COMPLETION_RING_SIZE, &this->ringSize,
            sizeof(this->ringSize));
    ASSERT_FRE(res == S_OK);

	// 4. Register rxring's size on InBound path
    if (this->flags.rx) {
        printf_verbose("configuring rx ring with size %d\n", this->ringSize);
        res =
            XskSetSockopt(
                this->sock, XSK_SOCKOPT_RX_RING_SIZE, &this->ringSize,
                sizeof(this->ringSize));
        ASSERT_FRE(res == S_OK);
        bindFlags |= XSK_BIND_FLAG_RX;
    }
	
    // 5. Register txring's size on OutBound path
    if (this->flags.tx) {
        printf_verbose("configuring tx ring with size %d\n", this->ringSize);
        res =
            XskSetSockopt(
                this->sock, XSK_SOCKOPT_TX_RING_SIZE, &this->ringSize,
                sizeof(this->ringSize));
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

    // 6. Bind the sock with queueId
	printf_verbose(
		"binding sock to ifindex %d queueId %d flags 0x%x\n", ifindex, this->queueId, bindFlags);
	res = XskBind(this->sock, ifindex, this->queueId, (XSK_BIND_FLAGS)bindFlags);
	ASSERT_FRE(res == S_OK);

    // 7.  Activate the sock
	printf_verbose("activating sock\n");
	res = XskActivate(this->sock, (XSK_ACTIVATE_FLAGS)0);
	ASSERT_FRE(res == S_OK);

    // 8. Get the ring infoSet to reset
	printf_verbose("XSK_SOCKOPT_RING_INFO\n");
	XSK_RING_INFO_SET infoSet = { 0 };
	UINT32 ringInfoSize = sizeof(infoSet);
	res = XskGetSockopt(this->sock, XSK_SOCKOPT_RING_INFO, &infoSet, &ringInfoSize);
	ASSERT_FRE(res == S_OK);
	ASSERT_FRE(ringInfoSize == sizeof(infoSet));
	PrintRingInfo(infoSet);

    // 9. Initialize the ring.
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

BOOL RssQueue::attachXdpProgram(INT ifindex) {
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

BOOL RssQueue::initFreeRing() {
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
    if (this->txPayload != NULL) {
        printf("Filling free ring with %d descriptors with payload size %d, the Payload header is generated by the Adapter info.\n", 
			numDescriptors, this->payloadsize);
		UINT32 genPacketSize;
		BYTE MtuBuffer[2048];
		memset(MtuBuffer, 0, sizeof(MtuBuffer));
        g_LocalAdapter->MTUFromPayload(this->txPayload, this->payloadsize, MtuBuffer, genPacketSize, kDefaultUDPTTL);

        UINT64 desc = 0;
        for (UINT32 i = 0; i < numDescriptors; i++) {
            UINT64* Descriptor = (UINT64*)XskRingGetElement(&this->freeRxRing, i);
            *Descriptor = desc;

            if (workMode == ModeTx || workMode == ModeLat) {
                memcpy(
                    (UCHAR*)this->umemReg.Address + desc + this->umemHeadroom,
                    MtuBuffer,
                    genPacketSize);
            }

            desc += this->umemchunkSize;
        }

        XskRingProducerSubmit(&this->freeRxRing, numDescriptors);
    }
    else {
        printf("Filling free ring with %d descriptors with payload size %d, the Payload header is copied from pre-assigned data.\n", 
			numDescriptors, this->payloadsize);
        UINT64 desc = 0;
        for (UINT32 i = 0; i < numDescriptors; i++) {
            UINT64* Descriptor = (UINT64*)XskRingGetElement(&this->freeRxRing, i);
            *Descriptor = desc;

            if (workMode == ModeTx || workMode == ModeLat) {
                memcpy(
                    (UCHAR*)this->umemReg.Address + desc + this->umemHeadroom,
                    this->txPattern,
                    this->txPatternLength);
            }

            desc += this->umemchunkSize;
        }

        XskRingProducerSubmit(&this->freeRxRing, numDescriptors);
    }
    return TRUE;
}
 
INT
LatCmp(
    const void * A,
    const void * B
)
{
    const UINT64* a = (const UINT64*)A;
    const UINT64* b = (const UINT64*)B;
    return (*a > *b) - (*a < *b);
}

void RssQueue::ProcessPeriodicStats(){
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

void
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

void
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

    if (workMode == ModeLat) {
        //PrintFinalLatStats(this);
        PrintFinalLatStats();
    }
}

void
RssQueue::writeTxPackets(
    //RssQueue * Queue,
    UINT32 FreeConsumerIndex,
    UINT32 TxProducerIndex,
    UINT32 Count
)
{
    for (UINT32 i = 0; i < Count; i++) {
        UINT64* freeDesc = (UINT64*)XskRingGetElement(&this->freeRxRing, FreeConsumerIndex++);
        XSK_BUFFER_DESCRIPTOR* txDesc = (XSK_BUFFER_DESCRIPTOR*)XskRingGetElement(&this->txRing, TxProducerIndex++);

        txDesc->Address.BaseAddress = *freeDesc;
        //assert(Queue->umemReg.Headroom <= MAXUINT16);
        assert(this->umemReg.Headroom <= MAXUINT16);
        txDesc->Address.Offset = (UINT16)this->umemReg.Headroom;
        txDesc->Length = this->txiosize;
        //
        // This benchmark does not write data into the TX packet.
        //
        printf_verbose("Producing TX entry {address:%llu, offset:%llu, length:%d}\n",
            txDesc->Address.BaseAddress, txDesc->Address.Offset, txDesc->Length);
    }
}

void
RssQueue::notifyDriver(
    XSK_NOTIFY_FLAGS DirectionFlags
)
{
    HRESULT res;
    XSK_NOTIFY_RESULT_FLAGS notifyResult;

    if (this->flags.optimizePoking) {
        //
        // Ensure poke flags are read after writing producer/consumer indices.
        //
        XdpBarrierBetweenReleaseAndAcquire();

        if ((DirectionFlags & XSK_NOTIFY_FLAG_POKE_RX) && !XskRingProducerNeedPoke(&this->fillRing)) {
            DirectionFlags &= ~XSK_NOTIFY_FLAG_POKE_RX;
        }
        if ((DirectionFlags & XSK_NOTIFY_FLAG_POKE_TX) && !XskRingProducerNeedPoke(&this->txRing)) {
            DirectionFlags &= ~XSK_NOTIFY_FLAG_POKE_TX;
        }
    }

    this->pokesRequestedCount++;

    if (DirectionFlags != 0) {
        this->pokesPerformedCount++;
        res =
            XskNotifySocket(
                this->sock, DirectionFlags, WAIT_DRIVER_TIMEOUT_MS, &notifyResult);

        if (DirectionFlags & (XSK_NOTIFY_FLAG_WAIT_RX | XSK_NOTIFY_FLAG_WAIT_TX)) {
            ASSERT_FRE(res == S_OK || res == HRESULT_FROM_WIN32(ERROR_TIMEOUT));
        }
        else {
            ASSERT_FRE(res == S_OK);
            ASSERT_FRE(notifyResult == 0);
        }
    }
}

void
RssQueue::readCompletionPackets(
    UINT32 CompConsumerIndex,
    UINT32 FreeProducerIndex,
    UINT32 Count
)
{
    for (UINT32 i = 0; i < Count; i++) {
        UINT64* compDesc = (UINT64*)XskRingGetElement(&this->compRing, CompConsumerIndex++);
        UINT64* freeDesc = (UINT64*)XskRingGetElement(&this->freeRxRing, FreeProducerIndex++);

        *freeDesc = *compDesc;
        printf_verbose("Consuming COMP entry {address:%llu}\n", *compDesc);
    }
}

UINT32
RssQueue::ProcessTx(
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
            &this->compRing, &consumerIndex, &this->freeRxRing, &producerIndex, this->iobatchsize);
    if (available > 0) {
        //ReadCompletionPackets(this, consumerIndex, producerIndex, available);
        this->readCompletionPackets( consumerIndex, producerIndex, available);
        XskRingConsumerRelease(&this->compRing, available);
        XskRingProducerSubmit(&this->freeRxRing, available);

        processed += available;
        this->packetCount += available;

        if (XskRingProducerReserve(&this->txRing, MAXUINT32, &producerIndex) !=
            this->txRing.Size) {
            notifyFlags |= XSK_NOTIFY_FLAG_POKE_TX;
        }
    }

    if (reqBucket.IsActivated() ) {
        //
        // If the request bucket is activated, we can process TX packets
        // immediately without waiting for the completion ring to be filled.
        if (reqBucket.ConsumeTokens(1)) {
            available =
                RingPairReserve(
                    &this->freeRxRing, &consumerIndex, &this->txRing, &producerIndex, 1);
            if (available > 0) {
                //WriteTxPackets(this, consumerIndex, producerIndex, available);
                this->writeTxPackets(consumerIndex, producerIndex, available);
                XskRingConsumerRelease(&this->freeRxRing, available);
                XskRingProducerSubmit(&this->txRing, available);

                processed += available;
                notifyFlags |= XSK_NOTIFY_FLAG_POKE_TX;
            }
        }
    }
    else {
        available =
            RingPairReserve(
                &this->freeRxRing, &consumerIndex, &this->txRing, &producerIndex, this->iobatchsize);
        if (available > 0) {
            //WriteTxPackets(this, consumerIndex, producerIndex, available);
            this->writeTxPackets(consumerIndex, producerIndex, available);
            XskRingConsumerRelease(&this->freeRxRing, available);
            XskRingProducerSubmit(&this->txRing, available);

            processed += available;
            notifyFlags |= XSK_NOTIFY_FLAG_POKE_TX;
        }
    }

    if (Wait &&
        XskRingConsumerReserve(&this->compRing, 1, &consumerIndex) == 0 &&
        XskRingConsumerReserve(&this->freeRxRing, 1, &consumerIndex) == 0) {
        notifyFlags |= XSK_NOTIFY_FLAG_WAIT_TX;
    }

    if (this->pollMode == XSK_POLL_MODE_SOCKET) {
        //
        // If socket poll mode is supported by the program, always enable pokes.
        //
        notifyFlags |= XSK_NOTIFY_FLAG_POKE_TX;
    }

    if (notifyFlags != 0) {
        //NotifyDriver(Queue, notifyFlags);
        this->notifyDriver( notifyFlags);
    }

    return processed;
}

void
RssQueue::readRxPackets(
    UINT32 RxConsumerIndex,
    UINT32 FreeProducerIndex,
    UINT32 Count
)
{
    for (UINT32 i = 0; i < Count; i++) {
        XSK_BUFFER_DESCRIPTOR* rxDesc = (XSK_BUFFER_DESCRIPTOR*)XskRingGetElement(&this->rxRing, RxConsumerIndex++);
        UINT64* freeDesc = (UINT64*)XskRingGetElement(&this->freeRxRing, FreeProducerIndex++);

        *freeDesc = rxDesc->Address.BaseAddress;
        printf_verbose("Consuming RX entry   {address:%llu, offset:%llu, length:%d}\n",
            rxDesc->Address.BaseAddress, rxDesc->Address.Offset, rxDesc->Length);

        if (outputStdout) {
            void* pEthHdr =
                (void*)((UCHAR*)this->umemReg.Address + rxDesc->Address.BaseAddress + rxDesc->Address.Offset);
            PrintPacketMeta(pEthHdr);
        }
    }
}

void
RssQueue::writeFillPackets(
    UINT32 FreeConsumerIndex,
    UINT32 FillProducerIndex,
    UINT32 Count
)
{
    for (UINT32 i = 0; i < Count; i++) {
        UINT64* freeDesc = (UINT64*)XskRingGetElement(&this->freeRxRing, FreeConsumerIndex++);
        UINT64* fillDesc = (UINT64*)XskRingGetElement(&this->fillRing, FillProducerIndex++);

        *fillDesc = *freeDesc;
        printf_verbose("Producing FILL entry {address:%llu}}\n", *freeDesc);
    }
}


UINT32
RssQueue::ProcessRx(
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
            &this->rxRing, &consumerIndex, &this->freeRxRing, &producerIndex, this->iobatchsize);
    if (available > 0) {
        //ReadRxPackets(this, consumerIndex, producerIndex, available);
        this->readRxPackets(consumerIndex, producerIndex, available);
        XskRingConsumerRelease(&this->rxRing, available);
        XskRingProducerSubmit(&this->freeRxRing, available);

        processed += available;
        this->packetCount += available;
    }

    available =
        RingPairReserve(
            &this->freeRxRing, &consumerIndex, &this->fillRing, &producerIndex, this->iobatchsize);
    if (available > 0) {
        this->writeFillPackets(consumerIndex, producerIndex, available);
        XskRingConsumerRelease(&this->freeRxRing, available);
        XskRingProducerSubmit(&this->fillRing, available);

        processed += available;
        notifyFlags |= XSK_NOTIFY_FLAG_POKE_RX;
    }

    if (Wait &&
        XskRingConsumerReserve(&this->rxRing, 1, &consumerIndex) == 0 &&
        XskRingConsumerReserve(&this->freeRxRing, 1, &consumerIndex) == 0) {
        notifyFlags |= XSK_NOTIFY_FLAG_WAIT_RX;
    }

    if (this->pollMode == XSK_POLL_MODE_SOCKET) {
        //
        // If socket poll mode is supported by the program, always enable pokes.
        //
        notifyFlags |= XSK_NOTIFY_FLAG_POKE_RX;
    }

    if (notifyFlags != 0) {
        //NotifyDriver(this, notifyFlags);
        this->notifyDriver(notifyFlags);
    }

    return processed;
}

UINT32
RssQueue::ProcessFwd(
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
            &this->rxRing, &consumerIndex, &this->txRing, &producerIndex, this->iobatchsize);
    if (available > 0) {
        for (UINT32 i = 0; i < available; i++) {
            XSK_BUFFER_DESCRIPTOR* rxDesc = (XSK_BUFFER_DESCRIPTOR*)XskRingGetElement(&this->rxRing, consumerIndex++);
            XSK_BUFFER_DESCRIPTOR* txDesc = (XSK_BUFFER_DESCRIPTOR*)XskRingGetElement(&this->txRing, producerIndex++);

            printf_verbose("Consuming RX entry   {address:%llu, offset:%llu, length:%d}\n",
                rxDesc->Address.BaseAddress, rxDesc->Address.Offset, rxDesc->Length);

            txDesc->Address = rxDesc->Address;
            txDesc->Length = rxDesc->Length;

            if (this->flags.rxInject == this->flags.txInspect) {
                //
                // Swap MAC addresses.
                //
                CHAR* ethHdr =
                    (CHAR*)this->umemReg.Address + txDesc->Address.BaseAddress +
                    txDesc->Address.Offset;
                CHAR tmp[6];
                memcpy(tmp, ethHdr, sizeof(tmp));
                memcpy(ethHdr, ethHdr + 6, sizeof(tmp));
                memcpy(ethHdr + 6, tmp, sizeof(tmp));
            }

            printf_verbose("Producing TX entry {address:%llu, offset:%llu, length:%d}\n",
                txDesc->Address.BaseAddress, txDesc->Address.Offset, txDesc->Length);
        }

        XskRingConsumerRelease(&this->rxRing, available);
        XskRingProducerSubmit(&this->txRing, available);

        processed += available;
        notifyFlags |= XSK_NOTIFY_FLAG_POKE_TX;
    }

    //
    // Move packets from the completion ring to the free ring.
    //
    available =
        RingPairReserve(
            &this->compRing, &consumerIndex, &this->freeRxRing, &producerIndex, this->iobatchsize);
    if (available > 0) {
        for (UINT32 i = 0; i < available; i++) {
            UINT64* compDesc = (UINT64*)XskRingGetElement(&this->compRing, consumerIndex++);
            UINT64* freeDesc = (UINT64*)XskRingGetElement(&this->freeRxRing, producerIndex++);

            *freeDesc = *compDesc;

            printf_verbose("Consuming COMP entry {address:%llu}\n", *compDesc);
        }

        XskRingConsumerRelease(&this->compRing, available);
        XskRingProducerSubmit(&this->freeRxRing, available);

        processed += available;
        this->packetCount += available;

        if (XskRingProducerReserve(&this->txRing, MAXUINT32, &producerIndex) !=
            this->txRing.Size) {
            notifyFlags |= XSK_NOTIFY_FLAG_POKE_TX;
        }
    }

    //
    // Move packets from the free ring to the fill ring.
    //
    available =
        RingPairReserve(
            &this->freeRxRing, &consumerIndex, &this->fillRing, &producerIndex, this->iobatchsize);
    if (available > 0) {
        for (UINT32 i = 0; i < available; i++) {
            UINT64* freeDesc = (UINT64*)XskRingGetElement(&this->freeRxRing, consumerIndex++);
            UINT64* fillDesc = (UINT64*)XskRingGetElement(&this->fillRing, producerIndex++);

            *fillDesc = *freeDesc;

            printf_verbose("Producing FILL entry {address:%llu}\n", *freeDesc);
        }

        XskRingConsumerRelease(&this->freeRxRing, available);
        XskRingProducerSubmit(&this->fillRing, available);

        processed += available;
        notifyFlags |= XSK_NOTIFY_FLAG_POKE_RX;
    }

    if (Wait &&
        XskRingConsumerReserve(&this->rxRing, 1, &consumerIndex) == 0 &&
        XskRingConsumerReserve(&this->compRing, 1, &consumerIndex) == 0 &&
        XskRingConsumerReserve(&this->freeRxRing, 1, &consumerIndex) == 0) {
        notifyFlags |= (XSK_NOTIFY_FLAG_WAIT_RX | XSK_NOTIFY_FLAG_WAIT_TX);
    }

    if (this->pollMode == XSK_POLL_MODE_SOCKET) {
        //
        // If socket poll mode is supported by the program, always enable pokes.
        //
        notifyFlags |= (XSK_NOTIFY_FLAG_POKE_RX | XSK_NOTIFY_FLAG_POKE_TX);
    }

    if (notifyFlags != 0) {
        //NotifyDriver(this, notifyFlags);
        this->notifyDriver(notifyFlags);
    }

    return processed;
}

UINT32
RssQueue::ProcessLat(
    BOOLEAN Wait
){
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
            &this->rxRing, &consumerIndex, &this->fillRing, &producerIndex, this->iobatchsize);
    if (available > 0) {
        LARGE_INTEGER NowQpc;
        VERIFY(QueryPerformanceCounter(&NowQpc));

        for (UINT32 i = 0; i < available; i++) {
            XSK_BUFFER_DESCRIPTOR* rxDesc = (XSK_BUFFER_DESCRIPTOR*)XskRingGetElement(&this->rxRing, consumerIndex++);
            UINT64* fillDesc = (UINT64*)XskRingGetElement(&this->fillRing, producerIndex++);

            printf_verbose(
                "Consuming RX entry   {address:%llu, offset:%llu, length:%d}\n",
                rxDesc->Address.BaseAddress, rxDesc->Address.Offset,
                rxDesc->Length);

            INT64 UNALIGNED* Timestamp = (INT64 UNALIGNED*)
                ((CHAR*)this->umemReg.Address + rxDesc->Address.BaseAddress +
                    rxDesc->Address.Offset + this->txPatternLength);

            printf_verbose("latency: %lld\n", NowQpc.QuadPart - *Timestamp);

            if (this->latIndex < this->latSamplesCount) {
                this->latSamples[this->latIndex++] = NowQpc.QuadPart - *Timestamp;
            }

            *fillDesc = rxDesc->Address.BaseAddress;

            printf_verbose("Producing FILL entry {address:%llu}\n", *fillDesc);
        }

        XskRingConsumerRelease(&this->rxRing, available);
        XskRingProducerSubmit(&this->fillRing, available);

        processed += available;
        this->packetCount += available;

        notifyFlags |= XSK_NOTIFY_FLAG_POKE_RX;
    }

    //
    // Move frames from the TX completion ring to the free ring.
    //
    available =
        RingPairReserve(
            &this->compRing, &consumerIndex, &this->freeRxRing, &producerIndex, this->iobatchsize);
    if (available > 0) {
        //ReadCompletionPackets(this, consumerIndex, producerIndex, available);
        this->readCompletionPackets( consumerIndex, producerIndex, available);
        XskRingConsumerRelease(&this->compRing, available);
        XskRingProducerSubmit(&this->freeRxRing, available);
        processed += available;

        if (XskRingProducerReserve(&this->txRing, MAXUINT32, &producerIndex) !=
            this->txRing.Size) {
            notifyFlags |= XSK_NOTIFY_FLAG_POKE_TX;
        }
    }

    //
    // Move frames from the free ring to the TX ring, stamping the current time
    // onto each frame.
    //
    available =
        RingPairReserve(
            &this->freeRxRing, &consumerIndex, &this->txRing, &producerIndex, this->iobatchsize);
    if (available > 0) {
        LARGE_INTEGER NowQpc;
        VERIFY(QueryPerformanceCounter(&NowQpc));

        for (UINT32 i = 0; i < available; i++) {
            UINT64* freeDesc = (UINT64*)XskRingGetElement(&this->freeRxRing, consumerIndex++);
            XSK_BUFFER_DESCRIPTOR* txDesc = (XSK_BUFFER_DESCRIPTOR*)XskRingGetElement(&this->txRing, producerIndex++);

            INT64 UNALIGNED* Timestamp = (INT64 UNALIGNED*)
                ((CHAR*)this->umemReg.Address + *freeDesc +
                    this->umemReg.Headroom + this->txPatternLength);
            *Timestamp = NowQpc.QuadPart;

            txDesc->Address.BaseAddress = *freeDesc;
            assert(this->umemReg.Headroom <= MAXUINT16);
            txDesc->Address.Offset = this->umemReg.Headroom;
            txDesc->Length = this->txiosize;

            printf_verbose(
                "Producing TX entry {address:%llu, offset:%llu, length:%d}\n",
                txDesc->Address.BaseAddress, txDesc->Address.Offset, txDesc->Length);
        }

        XskRingConsumerRelease(&this->freeRxRing, available);
        XskRingProducerSubmit(&this->txRing, available);

        processed += available;
        notifyFlags |= XSK_NOTIFY_FLAG_POKE_TX;
    }

    if (Wait &&
        XskRingConsumerReserve(&this->rxRing, 1, &consumerIndex) == 0 &&
        XskRingConsumerReserve(&this->compRing, 1, &consumerIndex) == 0 &&
        XskRingConsumerReserve(&this->freeRxRing, 1, &consumerIndex) == 0) {
        notifyFlags |= (XSK_NOTIFY_FLAG_WAIT_RX | XSK_NOTIFY_FLAG_WAIT_TX);
    }

    if (this->pollMode == XSK_POLL_MODE_SOCKET) {
        //
        // If socket poll mode is supported by the program, always enable pokes.
        //
        notifyFlags |= (XSK_NOTIFY_FLAG_POKE_RX | XSK_NOTIFY_FLAG_POKE_TX);
    }

    if (notifyFlags != 0) {
        //NotifyDriver(this, notifyFlags);
        this->notifyDriver(notifyFlags);
    }

    return processed;
}

UINT32 RssQueue::IssueRequest() {
    UINT32 consumerIndex;
    UINT32 producerIndex;
    UINT32 available;

    this->lastTick = GetTickCount64();

    //
    // Fill up the RX fill ring. Once this initial fill is performed, the
    // RX fill ring and RX ring operate in a closed loop.
    //
    available = XskRingProducerReserve(&this->fillRing, this->ringSize, &producerIndex);
    ASSERT_FRE(available == this->ringSize);
    available = XskRingConsumerReserve(&this->freeRxRing, this->ringSize, &consumerIndex);
    ASSERT_FRE(available == this->ringSize);
    //WriteFillPackets(queue, consumerIndex, producerIndex, available);
    this->writeFillPackets(consumerIndex, producerIndex, available);
    XskRingConsumerRelease(&this->freeRxRing, available);
    XskRingProducerSubmit(&this->fillRing, available);

    return available;
}

void RssQueue::SetupSock(INT IfIndex){
    HRESULT res;
    //UINT32 bindFlags = 0;

    printf_verbose("creating sock\n");
    res = XskCreate(&this->sock);
    if (res != S_OK) {
        ABORT("err: XskCreate returned %d\n", res);
    }

    printf_verbose("XDP_UMEM_REG\n");

    this->initSharedMemory();
	
	this->initDataPath(IfIndex);

	this->initFreeRing();

    this->attachXdpProgram(IfIndex);

    if(reqPPS> 0) {
        reqBucket.InitTokenbucket(1, reqPPS);
    }
}


