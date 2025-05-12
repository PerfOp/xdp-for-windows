//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

#include <xdpapi.h>

#include <winsock2.h>

#include <stdio.h>

//
// Directly include some C++ headers that produce benign compiler warnings.
//
#pragma warning(push)
#pragma warning(disable:5252) // Multiple different types resulted in the same XFG type-hash D275361C54538B70; the PDB will only record information for one of them
#include <xlocnum>
#include <xlocale>
#pragma warning(pop)

#include <CppUnitTest.h>
#include <fntrace.h>

#include "xdptest.h"
#include "tests.h"
#include "util.h"
#include "tests.tmh"
#include "netport.h"



//
// Define a test method for a feature not yet officially released.
// Unfortunately, the vstest.console.exe runner seems unable to filter on
// arbitrary properties, so mark prerelease as priority 1.
//
#define TEST_METHOD_PRERELEASE(_Name) \
    BEGIN_TEST_METHOD_ATTRIBUTE(_Name) \
        TEST_PRIORITY(1) \
    END_TEST_METHOD_ATTRIBUTE() \
    TEST_METHOD(_Name)

//
// Test suite(s).
//

//
// Ensure our build system is defaulting to the latest supported API version.
//
C_ASSERT(XDP_API_VERSION == XDP_API_VERSION_LATEST);

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

VOID
StopTest()
{
    Assert::Fail(L"Stop test execution.");
}

VOID
LogTestFailure(
    _In_z_ PCWSTR File,
    _In_z_ PCWSTR Function,
    INT Line,
    _Printf_format_string_ PCWSTR Format,
    ...
    )
{
    static const INT Size = 128;
    WCHAR Buffer[Size];

    UNREFERENCED_PARAMETER(File);
    UNREFERENCED_PARAMETER(Function);
    UNREFERENCED_PARAMETER(Line);

    va_list Args;
    va_start(Args, Format);
    _vsnwprintf_s(Buffer, Size, _TRUNCATE, Format, Args);
    va_end(Args);

    TraceError("%S", Buffer);
    Logger::WriteMessage(Buffer);
}

VOID
LogTestWarning(
    _In_z_ PCWSTR File,
    _In_z_ PCWSTR Function,
    INT Line,
    _Printf_format_string_ PCWSTR Format,
    ...
    )
{
    static const INT Size = 128;
    WCHAR Buffer[Size];

    UNREFERENCED_PARAMETER(File);
    UNREFERENCED_PARAMETER(Function);
    UNREFERENCED_PARAMETER(Line);

    va_list Args;
    va_start(Args, Format);
    _vsnwprintf_s(Buffer, Size, _TRUNCATE, Format, Args);
    va_end(Args);

    TraceWarn("%S", Buffer);
    Logger::WriteMessage(Buffer);
}


namespace UnitTestExample
{
    TEST_CLASS(PacketTests)
    {
    public:
        TEST_METHOD(TestPacket) {
            char refBuffer[] = "123456789abccba98765432108004500003c000000000111a2d00a0201720a02016c10e104d20028d3090000000000000000000000000000000000000000000000000000000000000000\0";
            UINT32 refSize = (UINT32)strlen(refBuffer);
			BYTE* loadBuffer = (BYTE*)malloc(refSize/2);

            if (loadBuffer != NULL) {
                GetDescriptorPattern(loadBuffer, refSize, refBuffer);
            }
            BYTE* mtuBuffer = NULL;
            UINT32 PacketLength = 0;
            mtuBuffer = (BYTE*)InitUdpPacket("cb-a9-87-65-43-21", "10.2.1.114", 4321, "12-34-56-78-9a-bc", "10.2.1.108", 1234, 32, PacketLength);

            Assert::IsNotNull(mtuBuffer);
            if (loadBuffer != NULL) {
				for (UINT32 i = 0; i < refSize/2; i++) {
                    Assert::AreEqual(loadBuffer[i], mtuBuffer[i]);
				}
                free(loadBuffer);
            }
            if (mtuBuffer != NULL) {
                free(mtuBuffer);
            }
        }
        
		TEST_METHOD(TestDynamicPacket) {
			char refBuffer[] = "123456789abccba98765432108004500003c000000000111a2d00a0201720a02016c10e104d20028d3090000000000000000000000000000000000000000000000000000000000000000\0";
            UINT32 refSize = (UINT32)strlen(refBuffer);
			BYTE* loadBuffer = (BYTE*)malloc(refSize/2);

            if (loadBuffer != NULL) {
                GetDescriptorPattern(loadBuffer, refSize, refBuffer);
            }

            AdapterMeta localAdapter;
			localAdapter.SetTarget("10.2.1.108", "12-34-56-78-9a-bc", 1234);
			localAdapter.AssingLocal("10.2.1.114", "cb-a9-87-65-43-21", 4321);
			BYTE* mtuBuffer = (BYTE*)localAdapter.GenMTUBuffer(refBuffer, 32);
            Assert::IsNotNull(mtuBuffer);
            if (loadBuffer != NULL) {
				for (UINT32 i = 0; i < refSize/2; i++) {
                    Assert::AreEqual(loadBuffer[i], mtuBuffer[i]);
				}
                free(loadBuffer);
            }
            if (mtuBuffer != NULL) {
                free(mtuBuffer);
            }
		}
    };
}

