#include "netport.h"
#include "work_load.h"
#include "highperf_timer.h"

//#include <iostream>
#include <thread>
#include <windows.h>


struct Context {
    std::string name;
    uint32_t reqPPS{ 0 };
};

std::atomic<bool> isWorking(true);

void workerThread(Context ctx) {
    sTokenBucket tokenBucket;
    tokenBucket.InitTokenbucket(1, ctx.reqPPS); // Initialize token bucket with reqPPS tokens per second and a refill interval of 1000 ms
    while (isWorking.load()) {
        if (tokenBucket.ConsumeTokens(1)) {
            printf("Working thread is running...\n");
        }
        YieldProcessor();
    }
    printf("Working thread finished.\n");
}

void InitWorkerThread(UINT32 reqPPS) {
    Context ctx;
    ctx.name = "";
    ctx.reqPPS = reqPPS;

    std::thread t(workerThread, ctx);
}
