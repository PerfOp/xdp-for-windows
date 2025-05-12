//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

#include <xdpapi.h>

#include <winsock2.h>

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

#include "netport.h"
#include "xdptest.h"
#include "tests.h"
#include "util.h"
#include "tests.tmh"

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


class Calculator {
public:
    int Add(int a, int b) { return a + b; }
    int Subtract(int a, int b) { return a - b; }
};


namespace UnitTestExample
{
    TEST_CLASS(CalculatorTests)
    {
    public:
        TEST_METHOD(TestAdd)
        {
            Calculator calc;
            Assert::AreEqual(5, calc.Add(2, 3));
        }

        TEST_METHOD(TestSubtract)
        {
            Calculator calc;
            Assert::AreEqual(1, calc.Subtract(3, 2));
        }

        TEST_METHOD(TestPacket) {
            AdapterMeta adapterMeta;
            adapterMeta.getLocalByIP("10.12.6.2");
        }
    };
}

