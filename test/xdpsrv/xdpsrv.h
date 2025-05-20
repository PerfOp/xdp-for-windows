#pragma once

#pragma warning(disable:4200) // nonstandard extension used: zero-sized array in struct/union

#define Usage() PrintUsage(__LINE__)

#include "internal_utils.h"
#include "rss_queue.h"

class NetThread {
public:
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
};

