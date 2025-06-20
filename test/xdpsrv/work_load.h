//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

#pragma once

#include <atomic>
void InitWorkerThread();
extern std::atomic<bool> isWorking;
